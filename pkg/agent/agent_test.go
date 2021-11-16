package agent

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/hewlettpackard/roven/pkg/common"

	"github.com/google/go-tpm/tpm2"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	"github.com/spiffe/spire-plugin-sdk/plugintest"
	agentnodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/tpmdevid/tpmutil"
	common_devid "github.com/spiffe/spire/pkg/common/plugin/tpmdevid"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/tpmdevid"
	"github.com/spiffe/spire/test/tpmsimulator"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type attestorSuite struct {
	agentPlugin         *AttestorPlugin
	agentAttestorClient *agentnodeattestorv1.NodeAttestorPluginClient
	agentHCL            string

	psatData  *common.PSATData
	token     string
	tokenPath string
	sim       *tpmsimulator.TPMSimulator

	t       *testing.T
	require *require.Assertions
}

func (a *attestorSuite) loadAgentPlugin(agentHLC string) error {
	a.agentPlugin = New()

	a.agentAttestorClient = new(agentnodeattestorv1.NodeAttestorPluginClient)
	configClient := new(configv1.ConfigServiceClient)

	plugintest.ServeInBackground(a.t, plugintest.Config{
		PluginServer:   agentnodeattestorv1.NodeAttestorPluginServer(a.agentPlugin),
		PluginClient:   a.agentAttestorClient,
		ServiceServers: []pluginsdk.ServiceServer{configv1.ConfigServiceServer(a.agentPlugin)},
		ServiceClients: []pluginsdk.ServiceClient{configClient},
	})

	hcl := fmt.Sprintf(`
		cluster = "FOO"
		token_path = %q
		tpm_device_path = %q
		devid_cert_path = %q
		devid_priv_path = %q
		devid_pub_path = %q
		devid_password = %q
		owner_hierarchy_password = %q
		endorsement_hierarchy_password = %q
	`, a.tokenPath, common.TPMDevicePath, common.DevIDCertPath, common.DevIDPrivPath, common.DevIDPubPath,
		common.TPMPasswords.DevIDKey, common.TPMPasswords.OwnerHierarchy, common.TPMPasswords.EndorsementHierarchy)

	if agentHLC != "" {
		hcl = agentHLC
	}

	_, err := configClient.Configure(context.Background(), &configv1.ConfigureRequest{
		HclConfiguration: hcl,
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

func loadAgent(t *testing.T) attestorSuite {
	a := attestorSuite{
		t:        t,
		psatData: common.DefaultPSATData(),
		require:  require.New(t),
		sim:      common.SetupTPMSimulator(t),
	}
	a.createAndWriteToken()
	a.require.NoError(a.loadAgentPlugin(""))
	return a
}

func TestConfigError(t *testing.T) {
	tests := []struct {
		name           string
		psatData       *common.PSATData
		agentHclConfig string
		expectedErr    string
	}{
		{
			name:           "Poorly formatted HCL config",
			psatData:       common.DefaultPSATData(),
			agentHclConfig: "poorly formatted hcl",
			expectedErr:    "rpc error: code = InvalidArgument desc = unable to decode configuration",
		},
		{
			name:        "HCL config missing devid_cert_path",
			psatData:    common.DefaultPSATData(),
			expectedErr: "rpc error: code = InvalidArgument desc = invalid configuration: devid_cert_path is required",
		},
		{
			name:           "HCL config missing devid_cert_path",
			psatData:       common.DefaultPSATData(),
			agentHclConfig: `devid_cert_path = "any"`,
			expectedErr:    "rpc error: code = InvalidArgument desc = invalid configuration: devid_priv_path is required",
		},
		{
			name:           "HCL config missing devid_cert_path",
			psatData:       common.DefaultPSATData(),
			agentHclConfig: `devid_cert_path = "any" devid_priv_path = "any"`,
			expectedErr:    "rpc error: code = InvalidArgument desc = invalid configuration: devid_pub_path is required",
		},
		{
			name:           "HCL config missing cluster",
			psatData:       common.DefaultPSATData(),
			agentHclConfig: `devid_cert_path = "any" devid_priv_path = "any" devid_pub_path = "any"`,
			expectedErr:    "rpc error: code = InvalidArgument desc = invalid configuration: cluster is required",
		},
		{
			name:           "TPM auto detection failed",
			psatData:       common.DefaultPSATData(),
			agentHclConfig: `devid_cert_path = "any" devid_priv_path = "any" devid_pub_path = "any", cluster = "any"`,
			expectedErr:    "rpc error: code = Internal desc = tpm autodetection failed: not found",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			a := &attestorSuite{
				psatData: test.psatData,
				t:        t,
				require:  require.New(t),
				agentHCL: test.agentHclConfig,
			}
			err := a.loadAgentPlugin(test.agentHclConfig)
			a.require.Error(err)
			a.require.Contains(err.Error(), test.expectedErr, "unexpected server configuration error")
		})
	}
}
func TestAttestationFail(t *testing.T) {
	t.Run("Agent not configured", func(t *testing.T) {
		agentPlugin := New()
		agentAttestorClient := new(agentnodeattestorv1.NodeAttestorPluginClient)
		configClient := new(configv1.ConfigServiceClient)
		plugintest.ServeInBackground(t, plugintest.Config{
			PluginServer:   agentnodeattestorv1.NodeAttestorPluginServer(agentPlugin),
			PluginClient:   agentAttestorClient,
			ServiceServers: []pluginsdk.ServiceServer{configv1.ConfigServiceServer(agentPlugin)},
			ServiceClients: []pluginsdk.ServiceClient{configClient},
		})

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		agentStream, _ := agentAttestorClient.AidAttestation(ctx)
		_, err := agentStream.Recv()

		require.Error(t, err)
		require.Contains(t, err.Error(), "rpc error: code = FailedPrecondition desc = not configured")
	})

	t.Run("Token not found in path", func(t *testing.T) {
		agentPlugin := New()
		agentAttestorClient := new(agentnodeattestorv1.NodeAttestorPluginClient)
		configClient := new(configv1.ConfigServiceClient)
		plugintest.ServeInBackground(t, plugintest.Config{
			PluginServer:   agentnodeattestorv1.NodeAttestorPluginServer(agentPlugin),
			PluginClient:   agentAttestorClient,
			ServiceServers: []pluginsdk.ServiceServer{configv1.ConfigServiceServer(agentPlugin)},
			ServiceClients: []pluginsdk.ServiceClient{configClient},
		})
		agentPlugin.config = &attestorConfig{
			tokenPath: "/bad/path",
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		agentStream, _ := agentAttestorClient.AidAttestation(ctx)
		_, err := agentStream.Recv()

		require.Error(t, err)
		require.Contains(t, err.Error(), "rpc error: code = InvalidArgument desc = unable to load token")
	})

	t.Run("Failed to load DevID cert", func(t *testing.T) {
		a := loadAgent(t)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Forcing TPM reset
		a.require.NoError(a.sim.ManufactureReset())

		agentStream, _ := a.agentAttestorClient.AidAttestation(ctx)
		_, err := agentStream.Recv()

		a.require.Error(err)
		a.require.Contains(err.Error(), "rpc error: code = Internal desc = unable to start a new TPM session: cannot load DevID key on TPM")
	})

	t.Run("Failed to get EK", func(t *testing.T) {
		a := loadAgent(t)

		// Removing NV Index from TPM storage
		a.require.NoError(tpm2.NVUndefineSpace(a.sim, "", tpm2.HandlePlatform, tpmutil.EKCertificateHandleRSA))

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		agentStream, _ := a.agentAttestorClient.AidAttestation(ctx)
		_, err := agentStream.Recv()

		a.require.Error(err)
		a.require.Contains(err.Error(), "rpc error: code = Internal desc = unable to get endorsement certificate")
	})

	t.Run("Unable to unmarshal challenge", func(t *testing.T) {
		a := loadAgent(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		agentStream, err := a.agentAttestorClient.AidAttestation(ctx)
		a.require.NoError(err)

		_, err = agentStream.Recv()
		a.require.NoError(err)

		// Generates malformed challenge
		err = agentStream.Send(&agentnodeattestorv1.Challenge{
			Challenge: []byte{0101},
		})
		a.require.NoError(err)

		_, err = agentStream.Recv()
		a.require.Error(err)
		a.require.Contains(err.Error(), "rpc error: code = InvalidArgument desc = unable to unmarshall challenges")
	})

	t.Run("Empty credential activation challenge", func(t *testing.T) {
		a := loadAgent(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		agentStream, err := a.agentAttestorClient.AidAttestation(ctx)
		a.require.NoError(err)

		_, err = agentStream.Recv()
		a.require.NoError(err)

		// Generates invalid challenge
		badChallengePayload, err := json.Marshal(struct{}{})
		a.require.NoError(err)

		err = agentStream.Send(&agentnodeattestorv1.Challenge{
			Challenge: badChallengePayload,
		})
		a.require.NoError(err)

		_, err = agentStream.Recv()
		a.require.Error(err)
		a.require.Contains(err.Error(), "rpc error: code = Internal desc = received empty credential activation challenge from server")
	})

	t.Run("Unable to solve proof of possession", func(t *testing.T) {
		a := loadAgent(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		agentStream, err := a.agentAttestorClient.AidAttestation(ctx)
		a.require.NoError(err)

		_, err = agentStream.Recv()
		a.require.NoError(err)

		anyChallengePayload, err := json.Marshal(struct{}{})
		a.require.NoError(err)

		// Forcing TPM reset after receiving agent payload
		a.require.NoError(a.sim.ManufactureReset())

		err = agentStream.Send(&agentnodeattestorv1.Challenge{
			Challenge: anyChallengePayload,
		})
		a.require.NoError(err)

		_, err = agentStream.Recv()
		a.require.Error(err)
		a.require.Contains(err.Error(), "rpc error: code = Internal desc = unable to solve proof of possession challenge: failed to sign nonce")
	})
}

func TestAttestationSuccess(t *testing.T) {
	a := loadAgent(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start attestation
	agentStream, err := a.agentAttestorClient.AidAttestation(ctx)
	a.require.NoError(err)

	// Generate a challenge from the payload
	agentResponse, err := agentStream.Recv()
	a.require.NoError(err)

	attestationData := new(common.AttestationRequest)
	err = json.Unmarshal(agentResponse.GetPayload(), attestationData)
	a.require.NoError(err)

	devidAttestationData := &attestationData.DevIDAttestationRequest
	a.require.NotZerof(len(devidAttestationData.DevIDCert), "missing devID certificate")

	devIDCert, err := x509.ParseCertificate(devidAttestationData.DevIDCert[0])
	a.require.NoError(err, "unable to parse DevID certificate")

	devIDIntermediates := x509.NewCertPool()
	for _, intermediatesBytes := range devidAttestationData.DevIDCert[1:] {
		intermediate, err := x509.ParseCertificate(intermediatesBytes)
		a.require.NoError(err, "unable to parse DevID intermediate certificate %d: %v")
		devIDIntermediates.AddCert(intermediate)
	}

	// Issue a DevID challenge (to prove the possession of the DevID private key).
	devIDChallenge, err := newNonce(32)
	a.require.NoError(err, "unable to generate challenge")

	ekRoots, err := util.LoadCertPool(common.EndorsementBundlePath)
	a.require.NoError(err, "failed to load endorsement bundle")

	// Create DevID residency challenge
	var (
		nonce                   []byte
		credActivationChallenge *common_devid.CredActivation
	)
	credActivationChallenge, nonce, err = verifyDevIDResidency(devidAttestationData, ekRoots)
	a.require.NoError(err)

	challenge, err := json.Marshal(common_devid.ChallengeRequest{
		DevID:          devIDChallenge,
		CredActivation: credActivationChallenge,
	})
	a.require.NoError(err)

	// Send challenge to agent
	err = agentStream.Send(&agentnodeattestorv1.Challenge{
		Challenge: challenge,
	})
	a.require.NoError(err)

	// Fetch and validate challenge response
	marshalledChallenges, err := agentStream.Recv()
	a.require.NoError(err)

	challengeResponse := &common_devid.ChallengeResponse{}
	err = json.Unmarshal(marshalledChallenges.GetChallengeResponse(), challengeResponse)
	a.require.NoError(err, "unable to unmarshall challenges response")

	// Verify DevID challenge
	err = tpmdevid.VerifyDevIDChallenge(devIDCert, devIDChallenge, challengeResponse.DevID)
	a.require.NoError(err, "devID challenge verification failed")

	// Verify credential activation challenge
	err = tpmdevid.VerifyCredActivationChallenge(nonce, challengeResponse.CredActivation)
	a.require.NoError(err, "credential activation failed")
}

func newNonce(size int) ([]byte, error) {
	nonce, err := common_devid.GetRandomBytes(size)
	if err != nil {
		return nil, err
	}

	return nonce, nil
}

func isDevIDResidencyInfoComplete(attReq *common_devid.AttestationRequest) error {
	if len(attReq.AKPub) == 0 {
		return status.Error(codes.InvalidArgument, "missing attestation key public blob")
	}

	if len(attReq.DevIDPub) == 0 {
		return status.Error(codes.InvalidArgument, "missing DevID key public blob")
	}

	if len(attReq.EKCert) == 0 {
		return status.Error(codes.InvalidArgument, "missing endorsement certificate")
	}

	if len(attReq.EKPub) == 0 {
		return status.Error(codes.InvalidArgument, "missing endorsement key public blob")
	}

	return nil
}

func verifyDevIDResidency(attData *common_devid.AttestationRequest, ekRoots *x509.CertPool) (*common_devid.CredActivation, []byte, error) {
	// Check that request contains all the information required to validate DevID residency
	err := isDevIDResidencyInfoComplete(attData)
	if err != nil {
		return nil, nil, err
	}

	// Decode attestation data
	ekCert, err := x509.ParseCertificate(attData.EKCert)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "cannot parse endorsement certificate: %v", err)
	}

	devIDPub, err := tpm2.DecodePublic(attData.DevIDPub)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "cannot decode DevID key public blob: %v", err)
	}

	akPub, err := tpm2.DecodePublic(attData.AKPub)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "cannot decode attestation key public blob: %v", err)
	}

	ekPub, err := tpm2.DecodePublic(attData.EKPub)
	if err != nil {
		return nil, nil, status.Error(codes.InvalidArgument, "cannot decode endorsement key public blob")
	}

	// Verify the public part of the EK generated from the template is the same
	// than the one in the EK certificate.
	err = verifyEKsMatch(ekCert, ekPub)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "public key in EK certificate differs from public key created via EK template: %v", err)
	}

	// Verify EK chain of trust using the provided manufacturer roots.
	err = verifyEKSignature(ekCert, ekRoots)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "cannot verify EK signature: %v", err)
	}

	// Verify DevID resides in the same TPM than AK
	err = tpmdevid.VerifyDevIDCertification(&akPub, &devIDPub, attData.CertifiedDevID, attData.CertificationSignature)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "cannot verify that DevID is in the same TPM than AK: %v", err)
	}

	// Issue a credential activation challenge (to verify AK is in the same TPM than EK)
	challenge, nonce, err := tpmdevid.NewCredActivationChallenge(akPub, ekPub)
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "cannot generate credential activation challenge: %v", err)
	}

	return challenge, nonce, nil
}

func verifyEKsMatch(ekCert *x509.Certificate, ekPub tpm2.Public) error {
	keyFromCert, ok := ekCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("key from certificate is not an RSA key")
	}

	cryptoKey, err := ekPub.Key()
	if err != nil {
		return fmt.Errorf("cannot get template key: %w", err)
	}

	keyFromTemplate, ok := cryptoKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("key from template is not an RSA key")
	}

	if keyFromCert.E != keyFromTemplate.E {
		return errors.New("exponent mismatch")
	}

	if keyFromCert.N.Cmp(keyFromTemplate.N) != 0 {
		return errors.New("modulus mismatch")
	}

	return nil
}

func verifyEKSignature(ekCert *x509.Certificate, roots *x509.CertPool) error {
	// Check UnhandledCriticalExtensions for OIDs that we know what to do about
	// it (e.g. it's safe to ignore)
	subjectAlternativeNameOID := asn1.ObjectIdentifier{2, 5, 29, 17}
	unhandledExtensions := []asn1.ObjectIdentifier{}
	for _, oid := range ekCert.UnhandledCriticalExtensions {
		// Endorsement certificate's SAN is not fully processed by x509 package
		if !oid.Equal(subjectAlternativeNameOID) {
			unhandledExtensions = append(unhandledExtensions, oid)
		}
	}

	ekCert.UnhandledCriticalExtensions = unhandledExtensions

	_, err := ekCert.Verify(x509.VerifyOptions{
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		Roots:     roots,
	})
	if err != nil {
		return fmt.Errorf("endorsement certificate verification failed: %w", err)
	}

	return nil
}
