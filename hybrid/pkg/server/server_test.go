package hybrid_server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	agentstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/agentstore/v1"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/awsiid"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/azuremsi"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/gcpiit"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/k8spsat"

	"github.com/hewlettpackard/hybrid/pkg/common"
	"github.com/spiffe/spire/test/fakes/fakeagentstore"
	"github.com/spiffe/spire/test/plugintest"
	require "github.com/stretchr/testify/require"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func BuiltIn() catalog.BuiltIn {
	return builtin(&HybridPluginServer{})
}

func builtin(p *HybridPluginServer) catalog.BuiltIn {
	return catalog.MakeBuiltIn("hybrid-node-attestor",
		nodeattestorv1.NodeAttestorPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

var pluginsString = `plugins {
    k8s_psat {
        clusters = {
            "test-cluster" = {
                service_account_allow_list = ["production:spire-agent"]
            }
        }
    }
    aws_iid {
        access_key_id = "ACCESS_KEY_ID"
        secret_access_key = "SECRET_ACCESS_KEY"
    }
}`

var pluginsStringInvalidData = `plugins {
        k8s_psat {
        }
        aws_iid {
        }
      }`

var pluginsStringEmptyData = `plugins {}`

var coreSpireConfig configv1.CoreConfiguration = configv1.CoreConfiguration{
	TrustDomain: "example.org",
}

func TestMethodsThatParseHclConfig(t *testing.T) {
	plugin := HybridPluginServer{}

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

	require.Equal(t, "\n  clusters = {\n    \"test-cluster\" = {\n      service_account_allow_list = [\"production:spire-agent\"]\n    }\n  }\n", pluginsData["k8s_psat"], "k8s_psat plugin data was not extracted properly")
	require.Contains(t, pluginsData, "aws_iid", "Could not access aws_iid plugin by index after parsing")
	require.Equal(t, "\n  access_key_id     = \"ACCESS_KEY_ID\"\n  secret_access_key = \"SECRET_ACCESS_KEY\"\n", pluginsData["aws_iid"], "aws_iid plugin data was not extracted properly")
}

func TestSupportedPluginsInitialization(t *testing.T) {
	interceptor := new(InterceptorWrapper)
	plugin := HybridPluginServer{interceptor: interceptor}

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
	interceptor := new(InterceptorWrapper)
	plugin := HybridPluginServer{interceptor: interceptor}

	coreConfig := catalog.CoreConfig{
		TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
	}
	var errConfig error

	plugintest.Load(t, builtin(&plugin), nil,
		plugintest.CaptureConfigureError(&errConfig),
		plugintest.HostServices(agentstorev1.AgentStoreServiceServer(fakeagentstore.New())),
		plugintest.CoreConfig(coreConfig),
		plugintest.Configure(pluginsString),
	)
	require.NoError(t, errConfig, "Error configuring plugin: %w", errConfig)
	require.Len(t, plugin.pluginList, 2, "Plugins used by Hybrid node attestor failed to start.")

	interceptor = new(InterceptorWrapper)
	plugin = HybridPluginServer{interceptor: interceptor}
	plugintest.Load(t, builtin(&plugin), nil,
		plugintest.CaptureConfigureError(&errConfig),
		plugintest.HostServices(agentstorev1.AgentStoreServiceServer(fakeagentstore.New())),
		plugintest.CoreConfig(coreConfig),
		plugintest.Configure(pluginsStringInvalidData),
	)
	require.Error(t, errConfig, "Error configuring plugin: %v", errConfig)

	req := configv1.ConfigureRequest{HclConfiguration: pluginsStringEmptyData}

	_, errConfig = plugin.Configure(context.Background(), &req)

	error := status.Error(codes.FailedPrecondition, "No plugins supplied")

	if errConfig == nil || errConfig.Error() != error.Error() {
		t.Error("Plugins used by Hybrid node attestor failed to start.")
	}
}

func TestHybridPluginServerInterceptor(t *testing.T) {

	combinedPayloads := []byte("")
	stream := StreamMock{CombinedPayloads: &combinedPayloads}
	interceptor := new(HybridPluginServerInterceptor)

	interceptor.SetContext(context.WithValue(context.Background(), "testkey", "testval"))
	require.Equal(t, "testval", interceptor.Context().Value("testkey"), "Could not set interceptor context")

	interceptor.SetLogger(hclog.Default().Named("test_logger"))
	require.Equal(t, "test_logger", interceptor.logger.Name(), "Could not set interceptor logger")

	interceptor.setCustomStream(&stream)
	require.IsType(t, &StreamMock{}, interceptor.stream, "Could not set custom stream")
	require.Equal(t, &stream, interceptor.Stream(), "Could not get custom stream")

	interceptor.SetSpiffeID("spiffe://example.org/spire/agent/test")
	require.Equal(t, "spiffe://example.org/spire/agent/test", interceptor.SpiffeID(), "Could not set spiffe id")

	var req nodeattestorv1.AttestRequest
	req.Request = &nodeattestorv1.AttestRequest_ChallengeResponse{
		ChallengeResponse: []byte("testchallenge"),
	}
	interceptor.SetReq(&req)
	gotReq, errConfig := interceptor.Recv()
	require.NoError(t, errConfig, "Error receiving request: %w", errConfig)
	require.Equal(t, []byte("testchallenge"), gotReq.GetChallengeResponse(), "Could not set interceptor request")

	var newInterceptor ServerInterceptorInterface = interceptor.SpawnInterceptor()
	require.IsType(t, &HybridPluginServerInterceptor{}, newInterceptor, "Spawned interceptor is not of type HybridPluginServerInterceptor")
	require.Equal(t, interceptor.Context(), newInterceptor.Context(), "Spawned interceptor context is not equal to original interceptor context")
	require.Equal(t, interceptor.logger, newInterceptor.(*HybridPluginServerInterceptor).logger, "Spawned interceptor logger is not equal to original interceptor logger")
	require.Equal(t, interceptor.SpiffeID(), newInterceptor.SpiffeID(), "Spawned interceptor spiffe id is not equal to original interceptor spiffe id")
	require.Equal(t, interceptor.Stream(), newInterceptor.Stream(), "Spawned interceptor stream is not equal to original interceptor stream")
	require.Equal(t, interceptor.req, newInterceptor.(*HybridPluginServerInterceptor).req, "Spawned interceptor request is not equal to original interceptor request")
	require.Equal(t, interceptor.Response, newInterceptor.(*HybridPluginServerInterceptor).Response, "Spawned interceptor response is not equal to original interceptor response")
	require.Equal(t, interceptor.combinedSelectors, newInterceptor.CombinedSelectors(), "Spawned interceptor combined selectors is not equal to original interceptor combined selectors")
	require.Equal(t, interceptor.canReattest, newInterceptor.(*HybridPluginServerInterceptor).canReattest, "Spawned interceptor canReattest is not equal to original interceptor canReattest")

	interceptor.combinedSelectors = []string{}
	interceptor.spiffeID = ""
	err := interceptor.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				SelectorValues: []string{"test", "test2"},
				SpiffeId:       "spiffe://example.org/spire/agent/k8s_psat/test",
				CanReattest:    false,
			},
		},
	})
	require.NoError(t, err, "Error sending response: %w", err)

	require.Equal(t, "spiffe://example.org/spire/agent/k8s_psat/test", interceptor.SpiffeID(), "Could not set custom response spiffeID")

	require.Equal(t, []string{"test", "test2"}, interceptor.CombinedSelectors(), "Could not set custom response selector values")

	err = interceptor.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				SelectorValues: []string{"test3", "test4"},
				SpiffeId:       "spiffe://example.org/new/spiffeid",
				CanReattest:    true,
			},
		},
	})
	require.NoError(t, err, "Error sending response: %w", err)
	require.Equal(t, "spiffe://example.org/spire/agent/k8s_psat/test", interceptor.SpiffeID(), "SpiffeID was overwritten on second response: %q", interceptor.SpiffeID())
	require.Equal(t, []string{"test", "test2", "test3", "test4"}, interceptor.CombinedSelectors(), "Selector values not appended properly on second response: %q", interceptor.CombinedSelectors())
	require.Equal(t, []bool{false, true}, interceptor.CanReattest(), "CanReattest was not set properly on second response: %t", interceptor.CanReattest())

}

func TestHybridPluginServerFuncsAndAttest(t *testing.T) {

	interceptorFake := new(InterceptorWrapper)
	interceptorFake.returnError = nil

	hybridPlugin := HybridPluginServer{logger: hclog.Default().Named("old_log"), interceptor: interceptorFake}

	hybridPlugin.SetLogger(hclog.Default().Named("test_logger"))
	require.Equal(t, "test_logger", hybridPlugin.logger.Name(), "Could not set logger for hybrid plugin")

	coreConfig := catalog.CoreConfig{
		TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
	}
	var errConfig error

	plugintest.Load(t, builtin(&hybridPlugin), nil,
		plugintest.CaptureConfigureError(&errConfig),
		plugintest.HostServices(agentstorev1.AgentStoreServiceServer(fakeagentstore.New())),
		plugintest.CoreConfig(coreConfig),
		plugintest.Configure(pluginsString),
	)
	require.NoError(t, errConfig, "Error configuring plugin: %w", errConfig)
	require.Len(t, hybridPlugin.pluginList, 2, "Plugins used by Hybrid node attestor failed to start.")

	pluginOne := new(FakePlugin)
	pluginTwo := new(FakePlugin)
	pluginList := []common.Types{
		{PluginName: "k8s_psat", Plugin: pluginOne},
		{PluginName: "aws_iid", Plugin: pluginTwo},
	}

	interceptorFake.canReattest = []bool{true, false}
	hybridPlugin = HybridPluginServer{pluginList: pluginList, logger: hclog.Default(), interceptor: interceptorFake}

	combinedPayloads, err := json.Marshal(common.PluginMessageList{
		Messages: []common.PluginMessage{
			{
				PluginName: "k8s_psat",
				PluginData: []byte("a"),
			},
			{
				PluginName: "aws_iid",
				PluginData: []byte("b"),
			},
		}})
	require.NoError(t, err, "Parse of sample messages failed: %v", err)

	stream := StreamMock{CombinedPayloads: &combinedPayloads}
	stream.returnError = nil
	stream.Response = &nodeattestorv1.AttestResponse{}
	err = hybridPlugin.Attest(stream)
	require.NoError(t, err, "Attest of hybrid plugin failed: %v", err)
}

func TestHybridPluginErrors(t *testing.T) {

	pluginOne := new(FakePlugin)
	pluginTwo := new(FakePlugin)
	pluginTwo.returnError = status.Error(codes.InvalidArgument, "Plugin initialization error")
	pluginList := []common.Types{
		{PluginName: "k8s_psat", Plugin: pluginOne},
		{PluginName: "aws_iid", Plugin: pluginTwo},
	}
	interceptorFake := new(InterceptorWrapper)
	interceptorFake.returnError = nil
	hybridPlugin := HybridPluginServer{pluginList: pluginList, logger: hclog.Default(), interceptor: interceptorFake}

	combinedPayloads := []byte("a")
	stream := StreamMock{CombinedPayloads: &combinedPayloads}
	stream.returnError = nil

	err := hybridPlugin.Attest(stream)
	require.EqualError(t, err, "rpc error: code = InvalidArgument desc = unable to unmarshal payload: invalid character 'a' looking for beginning of value")

	combinedPayloads, err = json.Marshal(common.PluginMessageList{
		Messages: []common.PluginMessage{
			{
				PluginName: "k8s_psat",
				PluginData: []byte("a"),
			},
			{
				PluginName: "aws_iid",
				PluginData: []byte("b"),
			},
		}})
	require.NoError(t, err, "Error marshalling combined payloads: %w", err)

	stream = StreamMock{CombinedPayloads: &combinedPayloads}
	stream.returnError = nil
	stream.Response = &nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				SelectorValues: []string{"test", "test2"},
				SpiffeId:       "spiffe://example.org/spire/agent/k8s_psat/test",
			},
		},
	}
	err = hybridPlugin.Attest(stream)
	require.EqualError(t, err, "rpc error: code = Internal desc = Plugin initialization error")

	combinedPayloads, err = json.Marshal(common.PluginMessageList{
		Messages: []common.PluginMessage{
			{
				PluginName: "k8s_psaat",
				PluginData: []byte("a"),
			},
			{
				PluginName: "aws_iid",
				PluginData: []byte("b"),
			},
		}})
	require.NoError(t, err, "Error marshalling combined payloads: %w", err)

	stream = StreamMock{CombinedPayloads: &combinedPayloads}
	stream.returnError = nil
	stream.Response = &nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				SelectorValues: []string{"test", "test2"},
				SpiffeId:       "spiffe://example.org/spire/agent/k8s_psat/test",
			},
		},
	}
	err = hybridPlugin.Attest(stream)
	require.EqualError(t, err, "rpc error: code = InvalidArgument desc = plugin k8s_psaat not found")

	challengeStream := ChallengeStreamMock{}
	challengeStream.returnError = nil
	err = hybridPlugin.Attest(challengeStream)
	require.EqualError(t, err, "rpc error: code = InvalidArgument desc = request payload is required")

	stream.returnError = status.Error(codes.InvalidArgument, "Plugin atestation error")

	err = hybridPlugin.Attest(stream)
	require.EqualError(t, err, "rpc error: code = InvalidArgument desc = Plugin atestation error")

	stream.returnError = status.Error(codes.InvalidArgument, "Error sending response")
	err = hybridPlugin.Attest(stream)
	require.EqualError(t, err, "rpc error: code = InvalidArgument desc = Error sending response", "Attest failed with unexpected error: %v", err)

}

func TestSendResponse(t *testing.T) {
	interceptor := new(InterceptorWrapper)
	plugin := HybridPluginServer{interceptor: interceptor}

	coreConfig := catalog.CoreConfig{
		TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
	}
	var errConfig error
	fakeStore := fakeagentstore.New()
	plugintest.Load(t, builtin(&plugin), nil,
		plugintest.CaptureConfigureError(&errConfig),
		plugintest.HostServices(agentstorev1.AgentStoreServiceServer(fakeStore)),
		plugintest.CoreConfig(coreConfig),
		plugintest.Configure(pluginsString),
	)
	require.NoError(t, errConfig, "Error configuring plugin: %w", errConfig)
	require.Len(t, plugin.pluginList, 2, "Plugins used by Hybrid node attestor failed to start.")
	pluginOne := new(FakePlugin)
	pluginTwo := new(FakePlugin)
	pluginTwo.returnError = status.Error(codes.InvalidArgument, "Plugin initialization error")
	pluginList := []common.Types{
		{PluginName: "k8s_psat", Plugin: pluginOne},
		{PluginName: "aws_iid", Plugin: pluginTwo},
	}

	plugin.pluginList = pluginList
	interceptor.canReattest = []bool{}
	combinedPayloads := []byte("a")
	stream := StreamMock{CombinedPayloads: &combinedPayloads}
	stream.returnError = nil
	stream.Response = &nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				SelectorValues: []string{"test", "test2"},
				SpiffeId:       "spiffe://example.org/spire/agent/k8s_psat/test",
			},
		},
	}
	interceptor.setCustomStream(&stream)
	interceptor.spiffeid = ""
	interceptorList := []ServerInterceptorInterface{}
	interceptorList = append(interceptorList, interceptor.SpawnInterceptor())
	interceptorList = append(interceptorList, interceptor.SpawnInterceptor())
	interceptorList[0].(*InterceptorWrapper).canReattest = []bool{true}
	interceptorList[0].(*InterceptorWrapper).spiffeid = "spiffe://example.org/spire/agent/k8s_psat/test"
	interceptorList[1].(*InterceptorWrapper).canReattest = []bool{false}
	interceptorList[1].(*InterceptorWrapper).spiffeid = "spiffe://example.org/spire/agent/aws_iid/test"
	err := plugin.SendResponse(interceptorList)
	require.NoError(t, err, "SendResponse failed: %v", err)
	require.Equal(t, "spiffe://example.org/spire/agent/k8s_psat/test", interceptor.spiffeid, "Main interceptor spiffeid was not set")

	fakeStore.SetAgentInfo(&agentstorev1.AgentInfo{
		AgentId: "spiffe://example.org/spire/agent/aws_iid/test",
	})
	err = plugin.SendResponse(interceptorList)
	require.EqualError(t, err, "rpc error: code = PermissionDenied desc = attestation data has already been used to attest an agent")

	fakeStore.SetAgentErr("spiffe://example.org/spire/agent/aws_iid/test", status.Error(codes.InvalidArgument, "Error retrieving agentInfo"))
	err = plugin.SendResponse(interceptorList)
	require.EqualError(t, err, "rpc error: code = InvalidArgument desc = unable to get agent info: Error retrieving agentInfo", "SendResponse failed unexpectedly: %v", err)

}

func TestNew(t *testing.T) {
	hybridPlugin := New()
	require.NotNil(t, hybridPlugin, "New should return a non-nil value")
	require.IsType(t, &HybridPluginServer{}, hybridPlugin, "New should return a HybridPluginServer")
}

func TestResetInterceptor(t *testing.T) {
	req := nodeattestorv1.AttestRequest{Request: &nodeattestorv1.AttestRequest_Payload{Payload: nil}}
	resp := nodeattestorv1.AttestResponse{Response: &nodeattestorv1.AttestResponse_AgentAttributes{
		AgentAttributes: &nodeattestorv1.AgentAttributes{
			SelectorValues: []string{"test", "test2"},
			SpiffeId:       "spiffe://example.org/spire/agent/k8s_psat/test",
			CanReattest:    false,
		},
	}}
	interceptor := HybridPluginServerInterceptor{ctx: context.Background(), stream: StreamMock{}, logger: hclog.Default(), req: &req, Response: &resp,
		combinedSelectors: []string{"test"}, spiffeID: "spiffe", canReattest: []bool{true}}

	if interceptor.ctx == nil && interceptor.stream == nil && interceptor.logger == nil && interceptor.req == nil && interceptor.Response == nil &&
		interceptor.combinedSelectors == nil && interceptor.spiffeID == "" && interceptor.canReattest == nil {
		errors.New("Interceptor is empty")
	}

	interceptor.ResetInterceptor()

	if interceptor.ctx != nil && interceptor.stream != nil && interceptor.logger != nil && interceptor.req != nil && interceptor.Response != nil &&
		interceptor.combinedSelectors != nil && interceptor.spiffeID != "" && interceptor.canReattest != nil {
		errors.New("Cannot reset interceptor")
	}
}

// ------------------------------------------------------------------------------------------------------------------------

type FakePlugin struct {
	returnError error
	request     *nodeattestorv1.AttestRequest
	logger      hclog.Logger
}

func (f *FakePlugin) SetReturnError(err error) {
	f.returnError = err
}

func (f *FakePlugin) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {
	if f.returnError != nil {
		return f.returnError
	}
	f.request, f.returnError = stream.Recv()
	return f.returnError
}

func (f *FakePlugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	fmt.Println("configure fake ", f.returnError)
	if f.returnError != nil {
		return nil, f.returnError

	}

	return &configv1.ConfigureResponse{}, nil
}

func (f *FakePlugin) SetLogger(logger hclog.Logger) {
	f.logger = logger
}

// ----------------------------------------------------------------------------

type StreamMock struct {
	grpc.ServerStream
	CombinedPayloads *[]byte
	Response         *nodeattestorv1.AttestResponse

	returnError error
}

func (s StreamMock) Recv() (*nodeattestorv1.AttestRequest, error) {
	if s.returnError != nil {
		return nil, s.returnError
	}
	request := nodeattestorv1.AttestRequest{Request: &nodeattestorv1.AttestRequest_Payload{Payload: *s.CombinedPayloads}}
	return &request, nil
}

func (s StreamMock) Send(challenge *nodeattestorv1.AttestResponse) error {
	*s.Response = *challenge

	return s.returnError
}

func (s StreamMock) Context() context.Context {
	return context.Background()
}

type ChallengeStreamMock struct {
	grpc.ServerStream
	CombinedPayloads *[]byte
	Response         *nodeattestorv1.AttestResponse

	returnError error
}

func (s ChallengeStreamMock) Recv() (*nodeattestorv1.AttestRequest, error) {
	if s.returnError != nil {
		return nil, s.returnError
	}
	request := nodeattestorv1.AttestRequest{Request: &nodeattestorv1.AttestRequest_ChallengeResponse{}}
	return &request, nil
}

func (s ChallengeStreamMock) Send(challenge *nodeattestorv1.AttestResponse) error {
	*s.Response = *challenge

	return s.returnError
}

func (s ChallengeStreamMock) Context() context.Context {
	return context.Background()
}

// ----------------------------------------------------------------------------

type PluginWrapper struct {
	nodeattestorv1.NodeAttestor_AttestServer
}

func (pw *PluginWrapper) Context() context.Context {
	return context.Background()
}

// ------------------------------------------------------------------------------------------------------------------------

type InterceptorWrapper struct {
	returnError error
	stream      nodeattestorv1.NodeAttestor_AttestServer
	nodeattestorv1.NodeAttestor_AttestServer
	canReattest []bool
	spiffeid    string
}

func (iw *InterceptorWrapper) SetReturnError(err error) {
	iw.returnError = err
}

func (iw *InterceptorWrapper) Recv() (*nodeattestorv1.AttestRequest, error) {
	return nil, nil
}

func (iw *InterceptorWrapper) Send(resp *nodeattestorv1.AttestResponse) error {
	return nil
}

func (iw *InterceptorWrapper) setCustomStream(stream nodeattestorv1.NodeAttestor_AttestServer) {
	iw.stream = stream
}

func (iw *InterceptorWrapper) SetContext(ctx context.Context) {

}

func (iw *InterceptorWrapper) Context() context.Context {
	return nil
}

func (iw *InterceptorWrapper) SetLogger(logger hclog.Logger) {

}

func (iw *InterceptorWrapper) SendCombined() error {
	if iw.returnError != nil {
		return status.Errorf(codes.Internal, "Test Error: %v", iw.returnError)
	}

	return nil
}

func (iw *InterceptorWrapper) CanReattest() []bool {
	return iw.canReattest
}

func (iw *InterceptorWrapper) GetPayloads() [][]byte {
	return nil
}
func (iw *InterceptorWrapper) CombinedSelectors() []string {
	return nil
}

func (iw *InterceptorWrapper) SetReq(req *nodeattestorv1.AttestRequest) {
}

func (iw *InterceptorWrapper) SpiffeID() string {
	return iw.spiffeid
}

func (iw *InterceptorWrapper) Stream() nodeattestorv1.NodeAttestor_AttestServer {
	return iw.stream
}

func (iw *InterceptorWrapper) ResetInterceptor() {

}

func (iw *InterceptorWrapper) SetSpiffeID(spiffeID string) {
	iw.spiffeid = spiffeID
}

func (iw *InterceptorWrapper) SpawnInterceptor() ServerInterceptorInterface {
	return &InterceptorWrapper{
		returnError: iw.returnError,
		stream:      iw.stream,
		canReattest: iw.canReattest,
		spiffeid:    iw.spiffeid,
	}
}
