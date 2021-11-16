package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/hewlettpackard/roven/pkg/common"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	"github.com/spiffe/spire-plugin-sdk/plugintest"
	agentnodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	servernodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/tpmdevid/tpmutil"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/plugin/k8s"
	common_devid "github.com/spiffe/spire/pkg/common/plugin/tpmdevid"
	"github.com/spiffe/spire/test/tpmsimulator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestConfigError(t *testing.T) {
	tests := []struct {
		name            string
		psatData        *common.PSATData
		trustDomain     string
		serverHclConfig string
		expectedErr     string
	}{
		{
			name:            "Poorly formatted HCL config",
			psatData:        common.DefaultPSATData(),
			serverHclConfig: "poorly formatted hcl",
			expectedErr:     "rpc error: code = InvalidArgument desc = failed to decode configuration",
		},
		{
			name:        "Missing trust domain",
			psatData:    common.DefaultPSATData(),
			trustDomain: "",
			expectedErr: "rpc error: code = InvalidArgument desc = trust_domain is required",
		},
		{
			name:        "Missing cluster",
			psatData:    common.DefaultPSATData(),
			trustDomain: "any.domain",
			expectedErr: "rpc error: code = InvalidArgument desc = configuration must have at least one cluster",
		},
		{
			name:        "Missing allowed service account",
			psatData:    common.DefaultPSATData(),
			trustDomain: "any.domain",
			serverHclConfig: `
				clusters = {
					"any" = {
						service_account_allow_list = []
					}
				}`,
			expectedErr: `rpc error: code = InvalidArgument desc = cluster "any" configuration must have at least one service account allowed`,
		},
		{
			name:        "Missing devid certificate path",
			psatData:    common.DefaultPSATData(),
			trustDomain: "any.domain",
			serverHclConfig: `
				clusters = {
					"any" = {
						service_account_allow_list = ["SA1"]
					}
				}`,
			expectedErr: `rpc error: code = InvalidArgument desc = devid_ca_path is required`,
		},
		{
			name:        "Missing devid endorsement path",
			psatData:    common.DefaultPSATData(),
			trustDomain: "any.domain",
			serverHclConfig: `
				clusters = {
					"any" = {
						service_account_allow_list = ["SA1"]
						kube_config_file = ""
						allowed_pod_label_keys = ["PODLABEL-A"]
						allowed_node_label_keys = ["NODELABEL-A"]
					}
				}
				devid_ca_path = "/any/path"`,
			expectedErr: "rpc error: code = InvalidArgument desc = endorsement_ca_path is required",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			a := &attestorSuite{t: t}
			a.require = require.New(t)
			a.psatData = test.psatData
			a.createAndWriteToken()

			// load and configure server
			s := New()
			serverAttestorClient := new(servernodeattestorv1.NodeAttestorPluginClient)
			serverConfigClient := new(configv1.ConfigServiceClient)
			plugintest.ServeInBackground(t, plugintest.Config{
				PluginServer:   servernodeattestorv1.NodeAttestorPluginServer(s),
				PluginClient:   serverAttestorClient,
				ServiceServers: []pluginsdk.ServiceServer{configv1.ConfigServiceServer(s)},
				ServiceClients: []pluginsdk.ServiceClient{serverConfigClient},
			})
			_, err := serverConfigClient.Configure(context.Background(), &configv1.ConfigureRequest{
				HclConfiguration: test.serverHclConfig,
				CoreConfiguration: &configv1.CoreConfiguration{
					TrustDomain: test.trustDomain,
				},
			})

			a.require.Error(err)
			a.require.Contains(err.Error(), test.expectedErr, "unexpected server configuration error")
		})
	}
}

func TestAttestationSetupFail(t *testing.T) {
	t.Run("Server not configured", func(t *testing.T) {
		a := &attestorSuite{t: t}
		a.require = require.New(t)

		a.serverPlugin = New()
		a.serverAttestorClient = new(servernodeattestorv1.NodeAttestorPluginClient)
		configClient := new(configv1.ConfigServiceClient)
		plugintest.ServeInBackground(a.t, plugintest.Config{
			PluginServer:   servernodeattestorv1.NodeAttestorPluginServer(a.serverPlugin),
			PluginClient:   a.serverAttestorClient,
			ServiceServers: []pluginsdk.ServiceServer{configv1.ConfigServiceServer(a.serverPlugin)},
			ServiceClients: []pluginsdk.ServiceClient{configClient},
		})

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		serverStream, err := a.serverAttestorClient.Attest(ctx)
		a.require.NoError(err, "attest failed")
		_, err = serverStream.Recv()

		a.require.Error(err)
		a.require.Contains(err.Error(), "rpc error: code = FailedPrecondition desc = not configured")
	})
	t.Run("Empty payload", func(t *testing.T) {
		a := &attestorSuite{t: t}
		a.require = require.New(t)
		a.psatData = common.DefaultPSATData()

		a.createAndWriteToken()
		common.SetupTPMSimulator(t)
		a.require.NoError(a.loadServerPlugin())

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		serverStream, err := a.serverAttestorClient.Attest(ctx)
		a.require.NoError(err)

		err = serverStream.Send(&servernodeattestorv1.AttestRequest{})
		a.require.NoError(err, "failed to send attestation request")
		_, err = serverStream.Recv()

		a.require.Error(err)
		a.require.Contains(err.Error(), "rpc error: code = InvalidArgument desc = missing attestation payload")
	})
}

func TestAttestationFail(t *testing.T) {
	a := &attestorSuite{t: t}
	a.require = require.New(t)
	a.psatData = common.DefaultPSATData()
	a.createAndWriteToken()

	// Set up the main TPM simulator
	sim, err := tpmsimulator.New(common.TPMPasswords.EndorsementHierarchy, common.TPMPasswords.OwnerHierarchy)
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, sim.Close(), "unexpected error encountered closing simulator")
	})

	// Replace real openTPM with open simulator
	tpmutil.OpenTPM = sim.OpenTPM

	// Create DevID with intermediate cert
	provisioningCA, err := tpmsimulator.NewProvisioningCA(&tpmsimulator.ProvisioningConf{})
	require.NoError(t, err, "failed to generate new provisioning CA")

	common.DevID, err = sim.GenerateDevID(provisioningCA, tpmsimulator.RSA, common.TPMPasswords.DevIDKey)
	require.NoError(t, err, "failed to generate DevID")

	// Create a temporal directory to store configuration files
	dir := t.TempDir()
	common.WriteDevIDFiles(t, dir)

	// Write provisioning root certificates into temp directory
	common.DevIDBundlePath = path.Join(dir, "devid-provisioning-ca.pem")
	require.NoError(t, os.WriteFile(
		common.DevIDBundlePath,
		pemutil.EncodeCertificate(provisioningCA.RootCert),
		0600),
		"failed to write DevID bundle",
	)

	// Write endorsement root certificate into temp directory
	common.EndorsementBundlePath = path.Join(dir, "endorsement-ca.pem")
	require.NoError(t, os.WriteFile(
		common.EndorsementBundlePath,
		pemutil.EncodeCertificate(sim.GetEKRoot()),
		0600),
		"failed to write endorsement bundle",
	)

	// Create another DevID using the main TPM but signed by a different provisioning authority
	anotherProvisioningCA, err := tpmsimulator.NewProvisioningCA(&tpmsimulator.ProvisioningConf{})
	require.NoError(t, err, "failed to create another provisioning CA")

	devIDAnotherProvisioningCA, err := sim.GenerateDevID(anotherProvisioningCA, tpmsimulator.RSA, common.TPMPasswords.DevIDKey)
	require.NoError(t, err, "failed to create another DevID")

	// Create a TPM session to generate payload and challenge response data
	session, err := tpmutil.NewSession(&tpmutil.SessionConfig{
		DevicePath: "/dev/tpmrm0",
		DevIDPriv:  common.DevID.PrivateBlob,
		DevIDPub:   common.DevID.PublicBlob,
		Passwords:  common.TPMPasswords,
		Log:        hclog.NewNullLogger(),
	})
	require.NoError(t, err)

	// Get endorsement key certificate and public key
	ekCert, err := session.GetEKCert()
	a.require.NoError(err, "failed to get endorsement key certificate")
	ekPub, err := session.GetEKPublic()
	a.require.NoError(err, "failed to get endorsement public key")

	// The DevID public key is necessary to ensure the DevID residency
	devIDPub, err := ioutil.ReadFile(common.DevIDPubPath)
	a.require.NoError(err, "failed to open DevID public key")

	// Certify DevID is in the same TPM as AK
	id, sig, err := session.CertifyDevIDKey()
	a.require.NoError(err, "failed to certify DevID residency")

	tests := []struct {
		name          string
		psatData      *common.PSATData
		attRequest    common.AttestationRequest
		challengeResp *common_devid.ChallengeResponse
		createMockFn  func(*common.PSATData, string) *apiClientMock
		badToken      bool
		expectedErr   string
	}{
		{
			name:         "Failed to unmarshal",
			psatData:     common.DefaultPSATData(),
			createMockFn: createAPIClientMock,
			expectedErr:  `rpc error: code = InvalidArgument desc = missing cluster in attestation data`,
		},
		{
			name:     "Missing token",
			psatData: common.DefaultPSATData(),
			attRequest: common.AttestationRequest{
				PSATAttestationData: k8s.PSATAttestationData{
					Cluster: "FOO",
				},
			},
			createMockFn: createAPIClientMock,
			badToken:     true,
			expectedErr:  `rpc error: code = InvalidArgument desc = missing token in attestation data`,
		},
		{
			name:     "Failed to find configuration for provided cluster",
			psatData: common.DefaultPSATData(),
			attRequest: common.AttestationRequest{
				PSATAttestationData: k8s.PSATAttestationData{
					Cluster: "foo",
					Token:   a.token,
				},
			},
			createMockFn: createAPIClientMock,
			expectedErr:  `not configured for cluster "foo"`,
		},
		{
			name:     "Invalid token",
			psatData: common.DefaultPSATData(),
			attRequest: common.AttestationRequest{
				PSATAttestationData: k8s.PSATAttestationData{
					Cluster: "FOO",
					Token:   "Bad token",
				},
			},
			createMockFn: createAPIClientMock,
			badToken:     true,
			expectedErr:  `rpc error: code = Internal desc = unable to validate token with TokenReview API`,
		},
		{
			name:     "Token not authenticated",
			psatData: common.DefaultPSATData(),
			attRequest: common.AttestationRequest{
				PSATAttestationData: k8s.PSATAttestationData{
					Cluster: "FOO",
					Token:   a.token,
				},
			},
			createMockFn: func(psatData *common.PSATData, token string) *apiClientMock {
				clientMock := createAPIClientMock(psatData, token)
				clientMock.SetTokenStatus(token, createTokenStatus(psatData, false, defaultAudience))
				return clientMock
			},
			expectedErr: `rpc error: code = PermissionDenied desc = token not authenticated according to TokenReview API`,
		},
		{
			name:     "Failed to parse user from token",
			psatData: common.DefaultPSATData(),
			attRequest: common.AttestationRequest{
				PSATAttestationData: k8s.PSATAttestationData{
					Cluster: "FOO",
					Token:   a.token,
				},
			},
			createMockFn: func(psatData *common.PSATData, token string) *apiClientMock {
				clientMock := createAPIClientMock(psatData, token)
				badTokenStatus := &authv1.TokenReviewStatus{
					Authenticated: true,
					User: authv1.UserInfo{
						Extra: make(map[string]authv1.ExtraValue),
					},
					Audiences: defaultAudience,
				}
				clientMock.SetTokenStatus(token, badTokenStatus)
				return clientMock
			},
			expectedErr: `rpc error: code = Internal desc = fail to parse username from token review status`,
		},
		{
			name:     "Forbidden service account name",
			psatData: common.DefaultPSATData(),
			attRequest: common.AttestationRequest{
				PSATAttestationData: k8s.PSATAttestationData{
					Cluster: "FOO",
					Token:   a.token,
				},
			},
			createMockFn: func(psatData *common.PSATData, token string) *apiClientMock {
				return createAPIClientMock(&common.PSATData{
					Namespace:          "NS2",
					ServiceAccountName: "SA2",
				}, token)
			},
			expectedErr: `"NS2:SA2" is not an allowed service account`,
		},
		{
			name:     "Failed to get pod uid from token",
			psatData: common.DefaultPSATData(),
			attRequest: common.AttestationRequest{
				PSATAttestationData: k8s.PSATAttestationData{
					Cluster: "FOO",
					Token:   a.token,
				},
			},
			createMockFn: func(psatData *common.PSATData, token string) *apiClientMock {
				clientMock := createAPIClientMock(psatData, token)
				clientMock.status[token].User.Extra["authentication.kubernetes.io/pod-uid"] = nil
				return clientMock
			},
			expectedErr: "rpc error: code = Internal desc = fail to get pod UID from token review status",
		},
		{
			name:     "Failed to get pod uid from token",
			psatData: common.DefaultPSATData(),
			attRequest: common.AttestationRequest{
				PSATAttestationData: k8s.PSATAttestationData{
					Cluster: "FOO",
					Token:   a.token,
				},
			},
			createMockFn: func(psatData *common.PSATData, token string) *apiClientMock {
				clientMock := &apiClientMock{
					apiClientConfig: apiClientConfig{
						status: make(map[string]*authv1.TokenReviewStatus),
					},
				}
				clientMock.SetTokenStatus(token, createTokenStatus(psatData, true, defaultAudience))

				return clientMock
			},
			expectedErr: "rpc error: code = Internal desc = fail to get pod from k8s API server",
		},
		{
			name:     "Missing DevID attestation data",
			psatData: common.DefaultPSATData(),
			attRequest: common.AttestationRequest{
				PSATAttestationData: k8s.PSATAttestationData{
					Cluster: "FOO",
					Token:   a.token,
				},
			},
			createMockFn: createAPIClientMock,
			expectedErr:  `rpc error: code = InvalidArgument desc = no DevID certificate to attest`,
		},
		{
			name:     "Unable to parse DevID certificate",
			psatData: common.DefaultPSATData(),
			attRequest: common.AttestationRequest{
				PSATAttestationData: k8s.PSATAttestationData{
					Cluster: "FOO",
					Token:   a.token,
				},
				DevIDAttestationRequest: common_devid.AttestationRequest{
					DevIDCert: [][]byte{{01}, {0101}},
				},
			},
			createMockFn: createAPIClientMock,
			expectedErr:  `rpc error: code = InvalidArgument desc = unable to parse DevID certificate: x509: malformed certificate`,
		},
		{
			name:     "Unable to verify signature",
			psatData: common.DefaultPSATData(),
			attRequest: common.AttestationRequest{
				PSATAttestationData: k8s.PSATAttestationData{
					Cluster: a.psatData.Cluster,
					Token:   a.token,
				},
				DevIDAttestationRequest: common_devid.AttestationRequest{
					DevIDCert: devIDAnotherProvisioningCA.Chain(),
				},
			},
			createMockFn: createAPIClientMock,
			expectedErr:  `rpc error: code = InvalidArgument desc = unable to verify DevID signature: verification failed: x509: certificate signed by unknown authority`,
		},
		{
			name:     "Missing public attestation key blob",
			psatData: common.DefaultPSATData(),
			attRequest: common.AttestationRequest{
				PSATAttestationData: k8s.PSATAttestationData{
					Cluster: a.psatData.Cluster,
					Token:   a.token,
				},
				DevIDAttestationRequest: common_devid.AttestationRequest{
					DevIDCert: common.DevID.Chain(),
				},
			},
			createMockFn: createAPIClientMock,
			expectedErr:  `rpc error: code = InvalidArgument desc = missing attestation key public blob`,
		},
		{
			name:     "Failed to verify DevID in same TPM than AK",
			psatData: common.DefaultPSATData(),
			attRequest: common.AttestationRequest{
				PSATAttestationData: k8s.PSATAttestationData{
					Cluster: a.psatData.Cluster,
					Token:   a.token,
				},
				DevIDAttestationRequest: common_devid.AttestationRequest{
					DevIDCert: common.DevID.Chain(),
					DevIDPub:  devIDPub,
					EKCert:    ekCert,
					EKPub:     ekPub,
					AKPub:     session.GetAKPublic(),
				},
			},
			createMockFn: createAPIClientMock,
			expectedErr:  `rpc error: code = InvalidArgument desc = cannot verify that DevID is in the same TPM than AK`,
		},
		{
			name:     "Challenge verification failed",
			psatData: common.DefaultPSATData(),
			attRequest: common.AttestationRequest{
				PSATAttestationData: k8s.PSATAttestationData{
					Cluster: a.psatData.Cluster,
					Token:   a.token,
				},
				DevIDAttestationRequest: common_devid.AttestationRequest{
					DevIDCert:              common.DevID.Chain(),
					DevIDPub:               devIDPub,
					EKCert:                 ekCert,
					EKPub:                  ekPub,
					AKPub:                  session.GetAKPublic(),
					CertifiedDevID:         id,
					CertificationSignature: sig,
				},
			},
			challengeResp: nil,
			createMockFn:  createAPIClientMock,
			expectedErr:   `rpc error: code = InvalidArgument desc = devID challenge verification failed`,
		},
		{
			name:     "Credential activation failed",
			psatData: common.DefaultPSATData(),
			attRequest: common.AttestationRequest{
				PSATAttestationData: k8s.PSATAttestationData{
					Cluster: a.psatData.Cluster,
					Token:   a.token,
				},
				DevIDAttestationRequest: common_devid.AttestationRequest{
					DevIDCert:              common.DevID.Chain(),
					DevIDPub:               devIDPub,
					EKCert:                 ekCert,
					EKPub:                  ekPub,
					AKPub:                  session.GetAKPublic(),
					CertifiedDevID:         id,
					CertificationSignature: sig,
				},
			},
			challengeResp: &common_devid.ChallengeResponse{},
			createMockFn:  createAPIClientMock,
			expectedErr:   `rpc error: code = InvalidArgument desc = credential activation failed`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Spin up server plugin
			a.require.NoError(a.loadServerPlugin(), "failed to load server")
			a.serverPlugin.config.clusters[a.psatData.Cluster].client = test.createMockFn(a.psatData, a.token)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// Begin attestation
			serverStream, err := a.serverAttestorClient.Attest(ctx)
			a.require.NoError(err, "failed opening server Attest stream")

			payload, err := json.Marshal(test.attRequest)
			a.require.NoError(err, "failed to marshal testing payload")

			// Send attestation payload to plugin
			a.require.NoError(serverStream.Send(&servernodeattestorv1.AttestRequest{
				Request: &servernodeattestorv1.AttestRequest_Payload{
					Payload: payload,
				},
			}))
			a.require.NoError(err, "failed to send attestation request to server")

			// Fetch challenge request
			challenge, err := serverStream.Recv()
			if err != nil {
				a.require.Error(err)
				a.require.Contains(err.Error(), test.expectedErr)
				return
			}

			if test.challengeResp != nil {
				var unmarshalledChallenge common_devid.ChallengeRequest

				err = json.Unmarshal(challenge.GetChallenge(), &unmarshalledChallenge)
				a.require.NoError(err)

				devIDChallengeResponse, err := session.SolveDevIDChallenge(unmarshalledChallenge.DevID)
				a.require.NoError(err)

				test.challengeResp.DevID = devIDChallengeResponse
			}

			marshalledChallenge, err := json.Marshal(test.challengeResp)
			a.require.NoError(err)

			// Send challenge response back to the server
			a.require.NoError(serverStream.SendMsg(&agentnodeattestorv1.PayloadOrChallengeResponse{
				Data: &agentnodeattestorv1.PayloadOrChallengeResponse_ChallengeResponse{
					ChallengeResponse: marshalledChallenge,
				},
			}))

			_, err = serverStream.Recv()

			a.require.Contains(err.Error(), test.expectedErr)
		})
	}
}

type attestorSuite struct {
	serverPlugin         *AttestorPlugin
	serverAttestorClient *servernodeattestorv1.NodeAttestorPluginClient

	psatData  *common.PSATData
	token     string
	tokenPath string

	t       *testing.T
	require *require.Assertions
}

func (a *attestorSuite) loadServerPlugin() error {
	a.serverPlugin = New()

	a.serverAttestorClient = new(servernodeattestorv1.NodeAttestorPluginClient)
	configClient := new(configv1.ConfigServiceClient)
	plugintest.ServeInBackground(a.t, plugintest.Config{
		PluginServer:   servernodeattestorv1.NodeAttestorPluginServer(a.serverPlugin),
		PluginClient:   a.serverAttestorClient,
		ServiceServers: []pluginsdk.ServiceServer{configv1.ConfigServiceServer(a.serverPlugin)},
		ServiceClients: []pluginsdk.ServiceClient{configClient},
	})

	_, err := configClient.Configure(context.Background(), &configv1.ConfigureRequest{
		HclConfiguration: generateServerHCL(a.psatData),
		CoreConfiguration: &configv1.CoreConfiguration{
			TrustDomain: common.TrustDomain,
		},
	})

	return err
}

func (a *attestorSuite) createAndWriteToken() {
	var err error
	dir := a.t.TempDir()
	a.token, err = common.CreatePSAT(a.psatData.Namespace, a.psatData.PodName)
	require.NoError(a.t, err)
	a.tokenPath = common.WriteToken(a.t, dir, common.TokenRelativePath, a.token)
}

func generateServerHCL(p *common.PSATData) string {
	return fmt.Sprintf(`
		clusters = {
			"%s" = {
				service_account_allow_list = ["%s:%s"]
				kube_config_file = ""
				allowed_pod_label_keys = ["PODLABEL-A"]
				allowed_node_label_keys = ["NODELABEL-A"]
			}
		}
		devid_ca_path = %q
		devid_cert_path = %q
		endorsement_ca_path = %q
		`, p.Cluster, p.Namespace, p.ServiceAccountName, common.DevIDBundlePath, common.DevIDCertPath, common.EndorsementBundlePath)
}

type namespacedName struct {
	namespace string
	name      string
}

type apiClientConfig struct {
	status map[string]*authv1.TokenReviewStatus
	pods   map[namespacedName]*corev1.Pod
	nodes  map[string]*corev1.Node
}

type apiClientMock struct {
	mock.Mock
	apiClientConfig
}

func createAPIClientMock(psatData *common.PSATData, token string) *apiClientMock {
	clientMock := &apiClientMock{
		apiClientConfig: apiClientConfig{
			status: make(map[string]*authv1.TokenReviewStatus),
			pods:   make(map[namespacedName]*corev1.Pod),
			nodes:  make(map[string]*corev1.Node),
		},
	}

	clientMock.SetTokenStatus(token, createTokenStatus(psatData, true, defaultAudience))
	clientMock.SetPod(createPod(psatData.Namespace, psatData.PodName, psatData.NodeName, psatData.NodeIP))
	clientMock.SetNode(createNode(psatData.NodeName, psatData.NodeUID))

	return clientMock
}

func (c *apiClientMock) GetNode(ctx context.Context, nodeName string) (*corev1.Node, error) {
	node, ok := c.apiClientConfig.nodes[nodeName]
	if !ok {
		return nil, fmt.Errorf("node %s not found", nodeName)
	}
	return node, nil
}

func (c *apiClientMock) GetPod(ctx context.Context, namespace, podName string) (*corev1.Pod, error) {
	pod, ok := c.apiClientConfig.pods[namespacedName{namespace: namespace, name: podName}]
	if !ok {
		return nil, fmt.Errorf("pod %s/%s not found", namespace, podName)
	}
	return pod, nil
}

func (c *apiClientMock) ValidateToken(ctx context.Context, token string, audiences []string) (*authv1.TokenReviewStatus, error) {
	status, ok := c.apiClientConfig.status[token]
	if !ok {
		return nil, errors.New("no status configured by test for token")
	}
	if !cmp.Equal(status.Audiences, audiences) {
		return nil, fmt.Errorf("got audiences %q; expected %q", audiences, status.Audiences)
	}
	return status, nil
}

func (c *apiClientMock) SetNode(node *corev1.Node) {
	c.apiClientConfig.nodes[node.Name] = node
}

func (c *apiClientMock) SetPod(pod *corev1.Pod) {
	c.apiClientConfig.pods[namespacedName{namespace: pod.Namespace, name: pod.Name}] = pod
}

func (c *apiClientMock) SetTokenStatus(token string, status *authv1.TokenReviewStatus) {
	c.apiClientConfig.status[token] = status
}

func createPod(namespace, podName, nodeName string, hostIP string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      podName,
			Labels: map[string]string{
				"PODLABEL-A": "A",
				"PODLABEL-B": "B",
			},
		},
		Spec: corev1.PodSpec{
			NodeName: nodeName,
		},
		Status: corev1.PodStatus{
			HostIP: hostIP,
		},
	}
}

func createNode(nodeName, nodeUID string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: nodeName,
			UID:  types.UID(nodeUID),
			Labels: map[string]string{
				"NODELABEL-A": "A",
				"NODELABEL-B": "B",
			},
		},
	}
}

func createTokenStatus(tokenData *common.PSATData, authenticated bool, audience []string) *authv1.TokenReviewStatus {
	values := make(map[string]authv1.ExtraValue)
	values["authentication.kubernetes.io/pod-name"] = authv1.ExtraValue([]string{tokenData.PodName})
	values["authentication.kubernetes.io/pod-uid"] = authv1.ExtraValue([]string{tokenData.PodUID})
	return &authv1.TokenReviewStatus{
		Authenticated: authenticated,
		User: authv1.UserInfo{
			Username: fmt.Sprintf("system:serviceaccount:%s:%s", tokenData.Namespace, tokenData.ServiceAccountName),
			Extra:    values,
		},
		Audiences: audience,
	}
}
