package hybridagent

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hewlettpackard/hybrid/pkg/common"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/awsiid"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/azuremsi"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/gcpiit"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/k8spsat"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/stretchr/testify/require"
)

func builtin(p *HybridPluginAgent) catalog.BuiltIn {
	return catalog.MakeBuiltIn("hybrid-node-attestor",
		nodeattestorv1.NodeAttestorPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

var pluginsString = `
	plugins {
		k8s_psat {
			cluster = "hybrid-node-attestor"
		}
		aws_iid {
			accountId = 123456789
		}
	}`

var pluginsStringInvalidData = `
	plugins {
		k8s_psat {
		}
		invalid_plugin_name {
		}
	}`

var pluginsStringErrorData = `
	plugins {
		k8s_psat {
		}
		aws_iid {
			accountId {
				error=true
			}
		}
	}`

var pluginsStringEmptyData = `plugins {}`
var pluginsInvalidPlugins = `
	plugins {
		test_plugin{
		}
	}`
var k8sPayloadData = `
	{
		"cluster":"hybrid-node-attestor_fake",
		"token":"part1.part2.part3-part4-part5-part6-part7"
	}`
var awsPayloadData = `
	{
		"document":"{
			"accountId" : "123456789_TEST",
			"architecture" : "x86_64",
			"availabilityZone" : "us-east-2a",
			"billingProducts" : null,
			"devpayProductCodes" : null,
			"marketplaceProductCodes" : null,
			"imageId" : "ami-010203040506",
			"instanceId" : "i-010203040506",
			"instanceType" : "m5.large",
			"kernelId" : null,
			"pendingTime" : "2022-09-22T03:22:21Z",
			"privateIp" : "192.168.77.116",
			"ramdiskId" : null,
			"region" : "us-east-2",
			"version" : "2017-09-30"
		}",
		"signature":"eO4+90PuN8bZaIJjpBe1/mAzPhvSrrhLATwPFaOPzK5ZSUpsbVOuK2tXjMYkx+ora7mcaL0G45li\nbZLGUIee+DF/YZ8/5RuNf1Z8yn+5e2AqLvNhIsF5IOVZWk8yDvl/jBJCcW8GaRblldWdMoDiC2OA\nqVyRjyJCXUySNu0JADE="
	}`

// ------------------------------------------------------------------------------------------------------------------------

func TestNew(t *testing.T) {
	hybridPlugin := New()
	require.NotNil(t, hybridPlugin, "New should return a non-nil value")
	require.IsType(t, &HybridPluginAgent{}, hybridPlugin, "New should return a HybridPluginAgent")
}

func TestMethodsThatParseHclConfig(t *testing.T) {
	plugin := HybridPluginAgent{}

	pluginAstNode, err := plugin.decodeStringAndTransformToAstNode(pluginsString)

	require.NoError(t, err)
	require.Len(t, pluginAstNode, 2, "Could not transform HCL string configuration: %w", err)
	require.Contains(t, pluginAstNode, "k8s_psat", "Could not access k8s_psat plugin by index on ast node")
	require.Contains(t, pluginAstNode, "aws_iid", "Could not access aws_iid plugin by index on ast node")

	pluginNames, pluginsData := plugin.parseReceivedData(pluginAstNode)

	require.Len(t, pluginNames, 2, "Could not parse plugin names")
	require.Contains(t, pluginNames, "k8s_psat", "Could not access k8s_psat plugin by index after parsing")
	require.Contains(t, pluginNames, "aws_iid", "Could not access aws_iid plugin by index after parsing")

	require.Len(t, pluginsData, 2, "Could not parse plugin data")
	require.Contains(t, pluginsData, "k8s_psat", "Could not access k8s_psat plugin by index after parsing")
	require.Equal(t, "\n  cluster = \"hybrid-node-attestor\"\n", pluginsData["k8s_psat"], "k8s_psat plugin data was not extracted properly")
	require.Contains(t, pluginsData, "aws_iid", "Could not access aws_iid plugin by index after parsing")
	require.Equal(t, "\n  accountId = 123456789\n", pluginsData["aws_iid"], "aws_iid plugin data was not extracted properly")
}

func TestSupportedPluginsInitialization(t *testing.T) {
	plugin := HybridPluginAgent{logger: hclog.Default().Named("test_logger")}

	plugins, err := plugin.initPlugins([]string{"aws_iid", "k8s_psat", "azure_msi", "gcp_iit"})

	require.NoError(t, err)
	require.IsType(t, &awsiid.IIDAttestorPlugin{}, plugins[0].Plugin, "Could not initialize aws_iid plugin")
	require.IsType(t, &k8spsat.AttestorPlugin{}, plugins[1].Plugin, "Could not initialize k8s_psat plugin")
	require.IsType(t, &azuremsi.MSIAttestorPlugin{}, plugins[2].Plugin, "Could not initialize azure_msi plugin")
	require.IsType(t, &gcpiit.IITAttestorPlugin{}, plugins[3].Plugin, "Could not initialize gcp_iit plugin")

	plugins, err = plugin.initPlugins([]string{"aws_iid_test", "k8s_psat_test"})
	require.Error(t, err, "Error initializing supported plugins: %w", err)
	spiretest.RequireGRPCStatus(t, err, codes.FailedPrecondition, "please provide one of the supported plugins.")
	require.Len(t, plugins, 0, "Plugin list length should be 0 on unknown plugin names")

	plugins, err = plugin.initPlugins([]string{"aws_iid", "k8s_psat_test"})
	require.Error(t, err, "Error initializing supported plugins: %w", err)
	spiretest.RequireGRPCStatus(t, err, codes.FailedPrecondition, "please provide one of the supported plugins.")

	plugins, err = plugin.initPlugins([]string{"aws_iid_test", "k8s_psat"})
	require.Error(t, err, "Error initializing supported plugins: %w", err)
	spiretest.RequireGRPCStatus(t, err, codes.FailedPrecondition, "please provide one of the supported plugins.")
}

func TestHybridPluginConfiguration(t *testing.T) {
	var errConfig error
	coreConfig := catalog.CoreConfig{
		TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
	}

	plugin := HybridPluginAgent{}

	t.Run("No Error Config", func(t *testing.T) {
		plugintest.Load(t, builtin(&plugin), nil,
			plugintest.CaptureConfigureError(&errConfig),
			plugintest.CoreConfig(coreConfig),
			plugintest.Configure(pluginsString),
		)
		require.NoError(t, errConfig)
		require.Len(t, plugin.pluginList, 2, "Plugins used by Hybrid node attestor failed to start.")
	})

	t.Run("Error invalid plugin data", func(t *testing.T) {
		plugintest.Load(t, builtin(&plugin), nil,
			plugintest.CaptureConfigureError(&errConfig),
			plugintest.CoreConfig(coreConfig),
			plugintest.Configure(pluginsStringInvalidData),
		)
		require.EqualError(t, errConfig, "rpc error: code = FailedPrecondition desc = please provide one of the supported plugins.", "Error configuring plugin: %w", errConfig)
		require.Len(t, plugin.pluginList, 0, "All plugins used by Hybrid node attestor should fail on config with unsupported plugins.")
	})

	t.Run("Error invalid plugins", func(t *testing.T) {
		plugintest.Load(t, builtin(&plugin), nil,
			plugintest.CaptureConfigureError(&errConfig),
			plugintest.CoreConfig(coreConfig),
			plugintest.Configure(pluginsInvalidPlugins),
		)

		require.EqualError(t, errConfig, "rpc error: code = FailedPrecondition desc = please provide one of the supported plugins.", "Error configuring plugin: %w", errConfig)
		require.Len(t, plugin.pluginList, 0, "Hybrid node attestor should load no plugins on empty config.")
	})

	t.Run("Error plugins with empty data", func(t *testing.T) {
		plugintest.Load(t, builtin(&plugin), nil,
			plugintest.CaptureConfigureError(&errConfig),
			plugintest.CoreConfig(coreConfig),
			plugintest.Configure(pluginsStringEmptyData),
		)

		require.EqualError(t, errConfig, "rpc error: code = FailedPrecondition desc = no plugins supplied", "Error configuring plugin: %w", errConfig)
		require.Len(t, plugin.pluginList, 0, "Hybrid node attestor should load no plugins on empty config.")
	})

	t.Run("Plugins with error data", func(t *testing.T) {
		plugintest.Load(t, builtin(&plugin), nil,
			plugintest.CaptureConfigureError(&errConfig),
			plugintest.CoreConfig(coreConfig),
			plugintest.Configure(pluginsStringErrorData),
		)
		require.EqualError(t, errConfig, "rpc error: code = Internal desc = error configuring one of the supplied plugins. The error was rpc error: code = InvalidArgument desc = configuration missing cluster")
	})

	t.Run("Erros plugins with empty data 2", func(t *testing.T) {
		plugintest.Load(t, builtin(&plugin), nil,
			plugintest.CaptureConfigureError(&errConfig),
			plugintest.CoreConfig(coreConfig),
			plugintest.Configure(""),
		)

		require.EqualError(t, errConfig, "rpc error: code = FailedPrecondition desc = no plugins supplied", "Error configuring plugin: %w", errConfig)
		require.Len(t, plugin.pluginList, 0, "Hybrid node attestor should load no plugins on empty config.")
	})
}

func TestHybridPluginAgentAidAttestation(t *testing.T) {
	emptyPayload := []byte("")
	streamMock := StreamMock{Payload: &emptyPayload}
	stream := new(HybridPluginAgentInterceptor)
	stream.setCustomStream(streamMock)

	fakePayloadK8s := "Fake payload k8s_psat"
	fakePayloadAws := "Fake payload aws_iid"
	pluginK8s := new(FakePlugin)
	pluginK8s.setPlayoad([]byte(fakePayloadK8s))
	pluginAws := new(FakePlugin)
	pluginAws.setPlayoad([]byte(fakePayloadAws))
	pluginList := []common.Types{
		{PluginName: "k8s_psat", Plugin: pluginK8s},
		{PluginName: "aws_iid", Plugin: pluginAws},
	}

	hybridPlugin := HybridPluginAgent{pluginList: pluginList, logger: hclog.Default()}

	aidAttestation := hybridPlugin.AidAttestation(stream)
	payloadResult := common.PluginMessageList{}
	json.Unmarshal(stream.payload, &payloadResult)
	require.Equal(t, string(payloadResult.Messages[0].PluginName), "k8s_psat")
	require.Equal(t, string(payloadResult.Messages[0].PluginData), fakePayloadK8s)
	require.Equal(t, string(payloadResult.Messages[1].PluginName), "aws_iid")
	require.Equal(t, string(payloadResult.Messages[1].PluginData), fakePayloadAws)
	require.NoError(t, aidAttestation)

	pluginK8s.setReturnError(true)
	aidAttestation = hybridPlugin.AidAttestation(stream)
	require.Error(t, aidAttestation, "AidAttestation of hybrid plugin fails")
	require.EqualErrorf(t, aidAttestation, status.Errorf(codes.Internal, "an error occurred during AidAttestation of the k8s_psat plugin. The error was rpc error: code = InvalidArgument desc = AidAttestation error").Error(), "Could not set hybrid plugin logger")

	hybridPlugin.SetLogger(hclog.Default().Named("test_logger2"))
	require.Equal(t, "test_logger2", hybridPlugin.logger.Name(), "Could not set hybrid plugin logger")

	require.Panics(
		t,
		func() {
			hybridPlugin.SetLogger(nil)
			hybridPlugin.logger.Name()
		},
		"The hybrid plugin should panic if no logger is set",
	)

	expectedError := status.Error(codes.FailedPrecondition, "plugin initialization error")
	hybridPlugin.initStatus = expectedError
	aidAttestation = hybridPlugin.AidAttestation(stream)
	require.EqualError(t, aidAttestation, expectedError.Error(), "AidAttestation of hybrid plugin fails")

	pluginK8s = new(FakePlugin)
	pluginAws = new(FakePlugin)
	pluginAws.returnError = true
	pluginList = []common.Types{
		{PluginName: "k8s_psat", Plugin: pluginK8s},
		{PluginName: "aws_iid", Plugin: pluginAws},
	}

	hybridPlugin = HybridPluginAgent{pluginList: pluginList, logger: hclog.Default()}

	aidAttestation = hybridPlugin.AidAttestation(stream)
	require.EqualError(t, aidAttestation, "rpc error: code = Internal desc = an error occurred during AidAttestation of the aws_iid plugin. The error was rpc error: code = InvalidArgument desc = AidAttestation error", "Error calling plugin: %w", aidAttestation)
}

// ------------------------------------------------------------------------------------------------------------------------

type FakePlugin struct {
	returnError bool
	payload     []byte
}

func (f *FakePlugin) setReturnError(state bool) {
	f.returnError = state
}

func (f *FakePlugin) setPlayoad(payload []byte) {
	f.payload = payload
}

func (f *FakePlugin) AidAttestation(stream nodeattestorv1.NodeAttestor_AidAttestationServer) error {
	if f.returnError {
		return status.Error(codes.InvalidArgument, "AidAttestation error")
	}
	return stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{
			Payload: f.payload,
		},
	})
}

func (f *FakePlugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	fmt.Println("configure fake ", f.returnError)
	if f.returnError {
		return nil, status.Errorf(codes.Internal, "Error configuring one of the supplied plugins.")
	}

	return &configv1.ConfigureResponse{}, nil
}

// ------------------------------------------------------------------------------------------------------------------------

type StreamMock struct {
	grpc.ServerStream
	Payload *[]byte
}

func (s StreamMock) Recv() (*nodeattestorv1.Challenge, error) {
	challenge := nodeattestorv1.Challenge{Challenge: []byte("customStream")}
	return &challenge, nil
}

func (s StreamMock) Send(challenge *nodeattestorv1.PayloadOrChallengeResponse) error {
	payload := challenge.GetPayload()
	*(s.Payload) = payload
	return nil
}

func (s StreamMock) Context() context.Context {
	return context.WithValue(context.Background(), "testkey", "testval")
}

// ------------------------------------------------------------------------------------------------------------------------

type PluginWrapper struct {
	nodeattestorv1.NodeAttestor_AidAttestationServer
}

func (pw *PluginWrapper) Context() context.Context {
	return context.Background()
}

// ------------------------------------------------------------------------------------------------------------------------

type InterceptorWrapper struct {
	returnError bool
	message     common.PluginMessage
	name        string
	nodeattestorv1.NodeAttestor_AidAttestationServer
}

func (iw *InterceptorWrapper) SetLogger(logger hclog.Logger) {
	// implementation to comply with the interface
}

func (iw *InterceptorWrapper) SendCombined(common.PluginMessageList) error {
	if iw.returnError {
		return status.Error(codes.Internal, "Test Error")
	}

	return nil
}

func (iw *InterceptorWrapper) GetMessage() common.PluginMessage {
	return iw.message
}

func (iw *InterceptorWrapper) SetPluginName(name string) {
	iw.name = name
}

func (iw *InterceptorWrapper) setCustomStream(stream nodeattestorv1.NodeAttestor_AidAttestationServer) {
	// implementation to comply with the interface
}

func (iw *InterceptorWrapper) setReturnError(state bool) {
	iw.returnError = state
}

func SpawnInterceptorWrapper() AgentInterceptor {
	return &InterceptorWrapper{}
}
