package hybrid_agent

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	hclog "github.com/hashicorp/go-hclog"
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
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/stretchr/testify/require"
)

func BuiltIn() catalog.BuiltIn {
	return builtin(&HybridPluginAgent{})
}

func builtin(p *HybridPluginAgent) catalog.BuiltIn {
	return catalog.MakeBuiltIn("hybrid-node-attestor",
		nodeattestorv1.NodeAttestorPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

var pluginsString = `plugins {
		k8s_psat {
		cluster = "hybrid-node-attestor"
		}
		aws_iid {
		accountId = 728109058939   
		}
	}`

var pluginsStringInvalidData = `plugins {
		k8s_psat {
		}
		aws_iida {
		}
	  }`

var pluginsStringErrorData = `plugins {
k8s_psat {
}
aws_iid {
	accountId {
		error=true
	}
}
}`

var pluginsStringEmptyData = `plugins {}`
var payloadOneData = `{"cluster":"hybrid-node-attestor_fake","token":"part1.part2.part3-part4-part5--part6-part7"}`
var payloadTwoData = `{"document":"{\n  \"accountId\" : \"123456789_TEST\",\n  \"architecture\" : \"x86_64\",\n  \"availabilityZone\" : \"us-east-2a\",\n  \"billingProducts\" : null,\n  \"devpayProductCodes\" : null,\n  \"marketplaceProductCodes\" : null,\n  \"imageId\" : \"ami-010203040506\",\n  \"instanceId\" : \"i-010203040506\",\n  \"instanceType\" : \"m5.large\",\n  \"kernelId\" : null,\n  \"pendingTime\" : \"2022-09-22T03:22:21Z\",\n  \"privateIp\" : \"192.168.77.116\",\n  \"ramdiskId\" : null,\n  \"region\" : \"us-east-2\",\n  \"version\" : \"2017-09-30\"\n}","signature":"eO4+90PuN8bZaIJjpBe1/mAzPhvSrrhLATwPFaOPzK5ZSUpsbVOuK2tXjMYkx+ora7mcaL0G45li\nbZLGUIee+DF/YZ8/5RuNf1Z8yn+5e2AqLvNhIsF5IOVZWk8yDvl/jBJCcW8GaRblldWdMoDiC2OA\nqVyRjyJCXUySNu0JADE="}`

// ------------------------------------------------------------------------------------------------------------------------

func TestNew(t *testing.T) {
	hybridPlugin := New()
	require.NotNil(t, hybridPlugin, "New should return a non-nil value")
	require.IsType(t, &HybridPluginAgent{}, hybridPlugin, "New should return a HybridPluginAgent")
}

func TestMethodsThatParseHclConfig(t *testing.T) {
	interceptor := new(InterceptorWrapper)
	plugin := HybridPluginAgent{interceptor: interceptor}

	pluginAstNode, err := plugin.decodeStringAndTransformToAstNode(pluginsString)

	require.NoError(t, err, "Error decoding test string")
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
	require.Equal(t, "\n  accountId = 728109058939\n", pluginsData["aws_iid"], "aws_iid plugin data was not extracted properly")
}

func TestSupportedPluginsInitialization(t *testing.T) {
	interceptor := new(InterceptorWrapper)
	plugin := HybridPluginAgent{interceptor: interceptor}

	plugins, err := plugin.initPlugins([]string{"aws_iid", "k8s_psat", "azure_msi", "gcp_iit"})

	require.NoError(t, err, "Error initializing supported plugins: %w", err)
	require.IsType(t, &awsiid.IIDAttestorPlugin{}, plugins[0].Plugin, "Could not initialize aws_iid plugin")
	require.IsType(t, &k8spsat.AttestorPlugin{}, plugins[1].Plugin, "Could not initialize k8s_psat plugin")
	require.IsType(t, &azuremsi.MSIAttestorPlugin{}, plugins[2].Plugin, "Could not initialize azure_msi plugin")
	require.IsType(t, &gcpiit.IITAttestorPlugin{}, plugins[3].Plugin, "Could not initialize gcp_iit plugin")

	plugins, err = plugin.initPlugins([]string{"aws_iid_test", "k8s_psat_test"})
	require.Error(t, err, "Error initializing supported plugins: %w", err)
	require.Len(t, plugins, 0, "Plugin list length should be 0 on unknown plugin names")

}

func TestHybridPluginConfiguration(t *testing.T) {
	var errConfig error
	coreConfig := catalog.CoreConfig{
		TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
	}

	interceptor := new(InterceptorWrapper)
	plugin := HybridPluginAgent{interceptor: interceptor}

	plugintest.Load(t, builtin(&plugin), nil,
		plugintest.CaptureConfigureError(&errConfig),
		plugintest.CoreConfig(coreConfig),
		plugintest.Configure(pluginsString),
	)
	require.NoError(t, errConfig, "Error configuring plugin: %w", errConfig)
	require.Len(t, plugin.pluginList, 2, "Plugins used by Hybrid node attestor failed to start.")

	interceptor = new(InterceptorWrapper)
	plugin = HybridPluginAgent{interceptor: interceptor}

	plugintest.Load(t, builtin(&plugin), nil,
		plugintest.CaptureConfigureError(&errConfig),
		plugintest.CoreConfig(coreConfig),
		plugintest.Configure(pluginsStringInvalidData),
	)
	require.EqualError(t, errConfig, "rpc error: code = FailedPrecondition desc = Some of the supplied plugins are not supported or are invalid", "Error configuring plugin: %w", errConfig)
	require.Len(t, plugin.pluginList, 0, "All plugins used by Hybrid node attestor should fail on config with unsupported plugins.")

	interceptor = new(InterceptorWrapper)
	plugin = HybridPluginAgent{interceptor: interceptor}

	plugintest.Load(t, builtin(&plugin), nil,
		plugintest.CaptureConfigureError(&errConfig),
		plugintest.CoreConfig(coreConfig),
		plugintest.Configure(pluginsStringEmptyData),
	)

	require.EqualError(t, errConfig, "rpc error: code = FailedPrecondition desc = No plugins supplied", "Error configuring plugin: %w", errConfig)
	require.Len(t, plugin.pluginList, 0, "Hybrid node attestor should load no plugins on empty config.")

	interceptor = new(InterceptorWrapper)
	plugin = HybridPluginAgent{interceptor: interceptor}

	plugintest.Load(t, builtin(&plugin), nil,
		plugintest.CaptureConfigureError(&errConfig),
		plugintest.CoreConfig(coreConfig),
		plugintest.Configure(pluginsStringErrorData),
	)
	require.EqualError(t, errConfig, "rpc error: code = Internal desc = Error configuring one of the supplied plugins.", "Error configuring plugin: %w", errConfig)
}

func TestHybridPluginAgentInterceptor(t *testing.T) {
	emptyPayload := []byte("")
	stream := StreamMock{Payload: &emptyPayload}
	interceptor := new(HybridPluginAgentInterceptor)

	interceptor.setCustomStream(&stream)
	customStream, _ := interceptor.Recv()
	require.Equal(t, []byte("customStream"), customStream.Challenge, "Could not set custom stream on interceptor")

	interceptor.SetContext(context.WithValue(context.Background(), "testkey", "testval"))
	customContext := interceptor.Context()
	require.Equal(t, "testval", customContext.Value("testkey"), "Could not set interceptor context")

	interceptor.SetLogger(hclog.Default().Named("test_logger"))
	require.Equal(t, "test_logger", interceptor.logger.Name(), "Could not set interceptor logger")

	payloadOne := nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{
			Payload: []byte(payloadOneData),
		},
	}
	interceptor.Send(&payloadOne)
	require.Equal(t, []byte(payloadOneData), interceptor.payload, "Could not set payload on interceptor")

	payloadTwo := nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{
			Payload: []byte(payloadTwoData),
		},
	}
	interceptor.Send(&payloadTwo)
	require.Equal(t, []byte(payloadTwoData), interceptor.payload, "Could not replace payload on interceptor")

	interceptor.payload = nil
	interceptorOne := interceptor.SpawnInterceptor()
	interceptorOne.SetPluginName("test_pluginOne")
	interceptorOne.Send(&payloadOne)

	interceptorTwo := interceptor.SpawnInterceptor()
	interceptorTwo.SetPluginName("test_pluginTwo")
	interceptorTwo.Send(&payloadTwo)
	var messageList common.PluginMessageList = common.PluginMessageList{}

	message1 := interceptorOne.GetMessage()
	require.Equal(t, []byte(payloadOneData), message1.PluginData, "Could not get message from interceptor")
	require.Equal(t, "test_pluginOne", message1.PluginName, "Could not get plugin name from interceptor")
	message2 := interceptorTwo.GetMessage()
	require.Equal(t, []byte(payloadTwoData), message2.PluginData, "Could not get message from interceptor")
	require.Equal(t, "test_pluginTwo", message2.PluginName, "Could not get plugin name from interceptor")
	messageList.Messages = append(messageList.Messages, message1)
	messageList.Messages = append(messageList.Messages, message2)
	interceptor.SendCombined(messageList)

	jsonMessage, err := json.Marshal(messageList)
	require.NoError(t, err, "Error marshalling message list: %w", err)
	require.Equal(t, &jsonMessage, stream.Payload, "Could not send combined message list to stream")
}

func TestHybridPluginAgentAidAttestation(t *testing.T) {

	emptyPayload := []byte("")
	stream := StreamMock{Payload: &emptyPayload}

	pluginOne := new(FakePlugin)
	pluginTwo := new(FakePlugin)
	pluginList := []common.Types{
		{PluginName: "k8s_psat", Plugin: pluginOne},
		{PluginName: "aws_iid", Plugin: pluginTwo},
	}
	interceptorFake := new(InterceptorWrapper)
	hybridPlugin := HybridPluginAgent{pluginList: pluginList, logger: hclog.Default(), interceptor: interceptorFake}

	aidAttestation := hybridPlugin.AidAttestation(stream)
	require.NoError(t, aidAttestation, "AidAttestation of hybrid plugin fails")
	interceptorFake.SetReturnError(true)

	aidAttestation = hybridPlugin.AidAttestation(stream)
	require.Error(t, aidAttestation, "AidAttestation of hybrid plugin fails")

	hybridPlugin.SetLogger(hclog.Default().Named("test_logger2"))
	require.Equal(t, "test_logger2", hybridPlugin.logger.Name(), "Could not set hybrid plugin logger")

	expectedError := status.Error(codes.InvalidArgument, "Plugin initialization error")
	hybridPlugin.initStatus = expectedError
	aidAttestation = hybridPlugin.AidAttestation(stream)
	require.EqualError(t, aidAttestation, expectedError.Error(), "AidAttestation of hybrid plugin fails")

	pluginOne = new(FakePlugin)
	pluginTwo = new(FakePlugin)
	pluginTwo.returnError = true
	pluginList = []common.Types{
		{PluginName: "k8s_psat", Plugin: pluginOne},
		{PluginName: "aws_iid", Plugin: pluginTwo},
	}
	interceptorFake = new(InterceptorWrapper)
	hybridPlugin = HybridPluginAgent{pluginList: pluginList, logger: hclog.Default(), interceptor: interceptorFake}

	aidAttestation = hybridPlugin.AidAttestation(stream)
	require.EqualError(t, aidAttestation, "rpc error: code = Internal desc = An error ocurred when during AidAttestation.", "Error calling plugin: %w", aidAttestation)
}

// ------------------------------------------------------------------------------------------------------------------------

type FakePlugin struct {
	returnError bool
}

func (f *FakePlugin) SetReturnError(state bool) {
	f.returnError = state
}

func (f *FakePlugin) AidAttestation(stream nodeattestorv1.NodeAttestor_AidAttestationServer) error {
	if f.returnError {
		return status.Error(codes.InvalidArgument, "AidAttestation error")
	}
	return nil
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
	return context.Background()
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

func (iw *InterceptorWrapper) SetReturnError(state bool) {
	iw.returnError = state
}

func (iw *InterceptorWrapper) Recv() (*nodeattestorv1.Challenge, error) {
	return nil, nil
}

func (iw *InterceptorWrapper) Send(challenge *nodeattestorv1.PayloadOrChallengeResponse) error {
	return nil
}

func (iw *InterceptorWrapper) setCustomStream(stream nodeattestorv1.NodeAttestor_AidAttestationServer) {

}

func (iw *InterceptorWrapper) SetContext(ctx context.Context) {

}

func (iw *InterceptorWrapper) Context() context.Context {
	return nil
}

func (iw *InterceptorWrapper) SetLogger(logger hclog.Logger) {

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

func (iw *InterceptorWrapper) SpawnInterceptor() AgentInterceptorInterface {
	return &InterceptorWrapper{
		returnError: iw.returnError,
		message:     iw.message,
		name:        iw.name,
	}
}
