package server

import (
	"context"
	"fmt"
	"testing"

	"github.com/hewlettpackard/roven/pkg/agent"
	"github.com/hewlettpackard/roven/pkg/common"

	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	"github.com/spiffe/spire-plugin-sdk/plugintest"
	agentnodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	servernodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/stretchr/testify/require"
)

func TestAttestorSuccess(t *testing.T) {
	a := &attestorSuite{t: t}
	common.SetupTPMSimulator(t)

	a.psatData = common.DefaultPSATData()
	a.require = require.New(t)
	a.createAndWriteToken()

	// Load agent plugin
	agentPlugin := agent.New()
	agentAttestorClient := new(agentnodeattestorv1.NodeAttestorPluginClient)
	configClient := new(configv1.ConfigServiceClient)
	plugintest.ServeInBackground(a.t, plugintest.Config{
		PluginServer:   agentnodeattestorv1.NodeAttestorPluginServer(agentPlugin),
		PluginClient:   agentAttestorClient,
		ServiceServers: []pluginsdk.ServiceServer{configv1.ConfigServiceServer(agentPlugin)},
		ServiceClients: []pluginsdk.ServiceClient{configClient},
	})
	_, err := configClient.Configure(context.Background(), &configv1.ConfigureRequest{
		HclConfiguration: fmt.Sprintf(`
		cluster = "FOO"
		token_path = %q
		tpm_device_path = %q
		devid_cert_path = %q
		devid_priv_path = %q
		devid_pub_path = %q
		devid_password = %q
		owner_hierarchy_password = %q
		endorsement_hierarchy_password = %q
	`, a.tokenPath, common.TPMDevicePath, common.DevIDCertPath, common.DevIDPrivPath, common.DevIDPubPath, common.TPMPasswords.DevIDKey, common.TPMPasswords.OwnerHierarchy, common.TPMPasswords.EndorsementHierarchy),
		CoreConfiguration: &configv1.CoreConfiguration{
			TrustDomain: common.TrustDomain,
		},
	})
	a.require.NoError(err)

	// Load server plugin
	serverPlugin := New()
	serverAttestorClient := new(servernodeattestorv1.NodeAttestorPluginClient)
	configClient = new(configv1.ConfigServiceClient)
	plugintest.ServeInBackground(a.t, plugintest.Config{
		PluginServer:   servernodeattestorv1.NodeAttestorPluginServer(serverPlugin),
		PluginClient:   serverAttestorClient,
		ServiceServers: []pluginsdk.ServiceServer{configv1.ConfigServiceServer(serverPlugin)},
		ServiceClients: []pluginsdk.ServiceClient{configClient},
	})
	_, err = configClient.Configure(context.Background(), &configv1.ConfigureRequest{
		HclConfiguration: fmt.Sprintf(`
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
		`, a.psatData.Cluster, a.psatData.Namespace, a.psatData.ServiceAccountName, common.DevIDBundlePath, common.DevIDCertPath, common.EndorsementBundlePath),
		CoreConfiguration: &configv1.CoreConfiguration{
			TrustDomain: common.TrustDomain,
		},
	})
	a.require.NoError(err)

	// Replace Plugin apiserver client with mock client
	serverPlugin.config.clusters[a.psatData.Cluster].client = createAPIClientMock(a.psatData, a.token)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start attestation
	agentStream, err := agentAttestorClient.AidAttestation(ctx)
	a.require.NoError(err)
	serverStream, err := serverAttestorClient.Attest(ctx)
	a.require.NoError(err)

	// Fetch agent response
	agentResp, err := agentStream.Recv()
	a.require.NoError(err)
	a.require.NotEmpty(agentResp.GetPayload(), "agent plugin responded with an empty payload")

	// Send agent response to server
	err = serverStream.Send(&servernodeattestorv1.AttestRequest{
		Request: &servernodeattestorv1.AttestRequest_Payload{
			Payload: agentResp.GetPayload(),
		},
	})
	a.require.NoError(err)

	// Fetch server response and send challenge request to agent
	serverResp, _ := serverStream.Recv()
	a.require.NotEmpty(serverResp.GetChallenge(), "server plugin responded with an empty challenge")
	err = agentStream.Send(&agentnodeattestorv1.Challenge{
		Challenge: serverResp.GetChallenge(),
	})
	a.require.NoError(err, "failed to send challenge request to agent")

	// Fetch agent response
	agentResp, _ = agentStream.Recv()
	a.require.Nil(agentResp.GetPayload(), "agent plugin responded with a payload instead of a challenge")
	a.require.NotEmpty(agentResp.GetChallengeResponse(), "agent plugin responded with an empty challenge response")

	// Send agent challenge response to server
	err = serverStream.Send(&servernodeattestorv1.AttestRequest{
		Request: &servernodeattestorv1.AttestRequest_ChallengeResponse{
			ChallengeResponse: agentResp.GetChallengeResponse(),
		},
	})
	a.require.NoError(err)

	// Fetch successful attestation response from server
	serverResp, err = serverStream.Recv()
	attribs := serverResp.GetAgentAttributes()
	a.require.NoError(err)
	a.require.NotNil(attribs)
}
