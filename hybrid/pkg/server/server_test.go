package hybridserver

import (
	"context"
	"encoding/json"
	"testing"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/hewlettpackard/hybrid/pkg/common"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	agentstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/agentstore/v1"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/awsiid"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/azuremsi"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/gcpiit"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/k8spsat"
	"github.com/spiffe/spire/test/fakes/fakeagentstore"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
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

func TestMethodsThatParseHclConfig(t *testing.T) {
	plugin := New()

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

	require.Equal(t, "\n  clusters = {\n    \"test-cluster\" = {\n      service_account_allow_list = [\"production:spire-agent\"]\n    }\n  }\n", pluginsData["k8s_psat"], "k8s_psat plugin data was not extracted properly")
	require.Contains(t, pluginsData, "aws_iid", "Could not access aws_iid plugin by index after parsing")
	require.Equal(t, "\n  access_key_id     = \"ACCESS_KEY_ID\"\n  secret_access_key = \"SECRET_ACCESS_KEY\"\n", pluginsData["aws_iid"], "aws_iid plugin data was not extracted properly")
}

func TestSupportedPluginsInitialization(t *testing.T) {
	plugin := HybridPluginServer{logger: hclog.Default().Named("test_logger")}

	plugins, err := plugin.initPlugins([]string{"aws_iid", "k8s_psat", "azure_msi", "gcp_iit"})

	require.NoError(t, err)
	require.IsType(t, &awsiid.IIDAttestorPlugin{}, plugins[0].Plugin, "Could not initialize aws_iid plugin")
	require.IsType(t, &k8spsat.AttestorPlugin{}, plugins[1].Plugin, "Could not initialize k8s_psat plugin")
	require.IsType(t, &azuremsi.MSIAttestorPlugin{}, plugins[2].Plugin, "Could not initialize azure_msi plugin")
	require.IsType(t, &gcpiit.IITAttestorPlugin{}, plugins[3].Plugin, "Could not initialize gcp_iit plugin")

	plugins, err = plugin.initPlugins([]string{"aws_iid_test", "k8s_psat_test"})
	require.Error(t, err, "Error initializing supported plugins: %w", err)
	require.Len(t, plugins, 0, "Plugin list length should be 0 on unknown plugin names")

}

func TestHybridPluginConfiguration(t *testing.T) {
	plugin := New()

	coreConfig := catalog.CoreConfig{
		TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
	}
	var errConfig error

	plugintest.Load(t, builtin(plugin), nil,
		plugintest.CaptureConfigureError(&errConfig),
		plugintest.HostServices(agentstorev1.AgentStoreServiceServer(fakeagentstore.New())),
		plugintest.CoreConfig(coreConfig),
		plugintest.Configure(pluginsString),
	)
	require.NoError(t, errConfig)
	require.Len(t, plugin.pluginList, 2, "Plugins used by Hybrid node attestor failed to start.")

	plugin = New()
	plugintest.Load(t, builtin(plugin), nil,
		plugintest.CaptureConfigureError(&errConfig),
		plugintest.HostServices(agentstorev1.AgentStoreServiceServer(fakeagentstore.New())),
		plugintest.CoreConfig(coreConfig),
		plugintest.Configure(pluginsStringInvalidData),
	)

	spiretest.RequireGRPCStatusContains(t, errConfig, codes.Internal, "getting data from one of the supplied plugins:")
	require.Error(t, errConfig, "Error configuring plugin: %v", errConfig)

	req := configv1.ConfigureRequest{HclConfiguration: pluginsStringEmptyData}

	_, errConfig = plugin.Configure(context.Background(), &req)

	spiretest.RequireGRPCStatus(t, errConfig, codes.FailedPrecondition, "no plugins supplied")
}

func TestHybridPluginServerFuncsAndAttest(t *testing.T) {
	hybridPlugin := HybridPluginServer{logger: hclog.Default().Named("old_log")}

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
	require.NoError(t, errConfig)
	require.Len(t, hybridPlugin.pluginList, 2, "Plugins used by Hybrid node attestor failed to start.")

	pluginPsat := new(FakePlugin)
	pluginPsat.setCustomReturnProperties(true, "spiffe://spiffe.psat", []string{"customSelectorOnePsat", "customSelectorTwoPsat"})
	pluginAws := new(FakePlugin)
	pluginAws.setCustomReturnProperties(false, "spiffe://spiffe.aws", []string{"customSelectorOneAws", "customSelectorTwoAws"})
	pluginList := []common.Types{
		{PluginName: "k8s_psat", Plugin: pluginPsat},
		{PluginName: "aws_iid", Plugin: pluginAws},
	}

	hybridPlugin = HybridPluginServer{logger: hclog.Default()}

	plugintest.Load(t, builtin(&hybridPlugin), nil,
		plugintest.CaptureConfigureError(&errConfig),
		plugintest.HostServices(agentstorev1.AgentStoreServiceServer(fakeagentstore.New())),
		plugintest.CoreConfig(coreConfig),
		plugintest.Configure(pluginsString),
	)

	hybridPlugin.pluginList = pluginList

	combinedPayloads, err := json.Marshal(common.PluginMessageList{
		Messages: []common.PluginMessage{
			{
				PluginName: "k8s_psat",
				PluginData: []byte(k8sPayloadData),
			},
			{
				PluginName: "aws_iid",
				PluginData: []byte(awsPayloadData),
			},
		}})
	require.NoError(t, err)

	stream := StreamMock{CombinedPayloads: &combinedPayloads}
	stream.returnError = nil
	stream.response = &nodeattestorv1.AttestResponse{}

	err_ := hybridPlugin.Attest(&stream)
	require.NoError(t, err_)

	require.Subset(t,
		stream.response.GetResponse().(*nodeattestorv1.AttestResponse_AgentAttributes).AgentAttributes.GetSelectorValues(),
		[]string{"customSelectorTwoPsat", "customSelectorOneAws"},
	)
	require.Equal(
		t,
		stream.response.GetResponse().(*nodeattestorv1.AttestResponse_AgentAttributes).AgentAttributes.GetCanReattest(),
		false,
	)
	require.Equal(
		t,
		stream.response.GetResponse().(*nodeattestorv1.AttestResponse_AgentAttributes).AgentAttributes.GetSpiffeId(),
		"spiffe://spiffe.psat",
	)
}

func TestHybridPluginErrors(t *testing.T) {

	pluginOne := new(FakePlugin)
	pluginTwo := new(FakePlugin)
	pluginTwo.returnError = status.Error(codes.InvalidArgument, "Plugin initialization error")
	pluginList := []common.Types{
		{PluginName: "k8s_psat", Plugin: pluginOne},
		{PluginName: "aws_iid", Plugin: pluginTwo},
	}

	hybridPlugin := HybridPluginServer{pluginList: pluginList, logger: hclog.Default()}

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
	require.NoError(t, err)

	stream = StreamMock{CombinedPayloads: &combinedPayloads}
	stream.returnError = nil
	stream.response = &nodeattestorv1.AttestResponse{
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
	require.NoError(t, err)

	stream = StreamMock{CombinedPayloads: &combinedPayloads}
	stream.returnError = nil
	stream.response = &nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				SelectorValues: []string{"test", "test2"},
				SpiffeId:       "spiffe://example.org/spire/agent/k8s_psat/test",
			},
		},
	}
	err = hybridPlugin.Attest(stream)
	require.EqualError(t, err, "rpc error: code = InvalidArgument desc = plugin k8s_psat not found")

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
	interceptor := new(HybridPluginServerInterceptor)
	plugin := New()

	coreConfig := catalog.CoreConfig{
		TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
	}
	var errConfig error
	fakeStore := fakeagentstore.New()
	plugintest.Load(t, builtin(plugin), nil,
		plugintest.CaptureConfigureError(&errConfig),
		plugintest.HostServices(agentstorev1.AgentStoreServiceServer(fakeStore)),
		plugintest.CoreConfig(coreConfig),
		plugintest.Configure(pluginsString),
	)
	require.NoError(t, errConfig)
	require.Len(t, plugin.pluginList, 2, "Plugins used by Hybrid node attestor failed to start.")
	pluginOne := new(FakePlugin)
	pluginTwo := new(FakePlugin)
	pluginTwo.returnError = status.Error(codes.InvalidArgument, "Plugin initialization error")
	pluginList := []common.Types{
		{PluginName: "k8s_psat", Plugin: pluginOne},
		{PluginName: "aws_iid", Plugin: pluginTwo},
	}

	plugin.pluginList = pluginList
	combinedPayloads := []byte("a")
	stream := StreamMock{CombinedPayloads: &combinedPayloads}
	stream.returnError = nil

	interceptorList := []ServerInterceptor{}
	interceptorList = append(interceptorList, interceptor.NewInterceptor())
	interceptorList = append(interceptorList, interceptor.NewInterceptor())
	interceptorList[0].(*HybridPluginServerInterceptor).canReattest = []bool{true}
	stream.response = &nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				SelectorValues: []string{"psat_selector_one", "psat_selector_two"},
				SpiffeId:       "spiffe://example.org/spire/agent/k8s_psat/test",
				CanReattest:    true,
			},
		},
	}
	interceptorList[0].setCustomStream(stream)
	interceptorList[0].Send(stream.response)
	interceptorList[1].(*HybridPluginServerInterceptor).canReattest = []bool{false}
	stream.response = &nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				SelectorValues: []string{"aws_selector_one", "aws_selector_two"},
				SpiffeId:       "spiffe://example.org/spire/agent/aws_iid/test",
				CanReattest:    false,
			},
		},
	}
	interceptorList[1].setCustomStream(stream)
	interceptorList[1].Send(stream.response)

	err := plugin.SendResponse(interceptorList, stream)
	require.NoError(t, err)
	require.Equal(
		t,
		"spiffe://example.org/spire/agent/k8s_psat/test",
		stream.response.GetResponse().(*nodeattestorv1.AttestResponse_AgentAttributes).AgentAttributes.GetSpiffeId(),
		"Main interceptor spiffeid was not set",
	)

	fakeStore.SetAgentInfo(&agentstorev1.AgentInfo{
		AgentId: "spiffe://example.org/spire/agent/aws_iid/test",
	})
	err = plugin.SendResponse(interceptorList, stream)
	require.EqualError(t, err, "rpc error: code = PermissionDenied desc = attestation data has already been used to attest an agent")

	fakeStore.SetAgentErr("spiffe://example.org/spire/agent/aws_iid/test", status.Error(codes.InvalidArgument, "Error retrieving agentInfo"))
	err = plugin.SendResponse(interceptorList, stream)
	require.EqualError(t, err, "rpc error: code = InvalidArgument desc = unable to get agent info: Error retrieving agentInfo", "SendResponse failed unexpectedly: %v", err)
}

func TestNew(t *testing.T) {
	hybridPlugin := New()
	require.NotNil(t, hybridPlugin, "New should return a non-nil value")
	require.IsType(t, &HybridPluginServer{}, hybridPlugin, "New should return a HybridPluginServer")
}

// ------------------------------------------------------------------------------------------------------------------------

type FakePlugin struct {
	returnError error
	request     *nodeattestorv1.AttestRequest
	logger      hclog.Logger
	canreattest bool
	spiffeId    string
	selectors   []string
}

func (f *FakePlugin) setCustomReturnProperties(canreattest bool, spiffeId string, selectors []string) {
	f.canreattest = canreattest
	f.spiffeId = spiffeId
	f.selectors = selectors
}

func (f *FakePlugin) SetReturnError(err error) {
	f.returnError = err
}

func (f *FakePlugin) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {
	if f.returnError != nil {
		return f.returnError
	}

	f.request, f.returnError = stream.Recv()
	if f.returnError != nil {
		return f.returnError
	}

	return stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				CanReattest:    f.canreattest,
				SpiffeId:       f.spiffeId,
				SelectorValues: f.selectors,
			},
		},
	})
}

func (f *FakePlugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
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
	response         *nodeattestorv1.AttestResponse

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
	*s.response = *challenge

	return s.returnError
}

func (s StreamMock) Context() context.Context {
	return context.Background()
}

// ----------------------------------------------------------------------------

type ChallengeStreamMock struct {
	grpc.ServerStream
	CombinedPayloads *[]byte
	response         *nodeattestorv1.AttestResponse

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
	*s.response = *challenge

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
	ctx         context.Context
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

func (iw *InterceptorWrapper) SetContext(ctx context.Context) {
	iw.ctx = ctx
}

func (iw *InterceptorWrapper) Context() context.Context {
	return iw.ctx
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

func (iw *InterceptorWrapper) NewInterceptor() ServerInterceptor {
	return &InterceptorWrapper{
		returnError: iw.returnError,
		stream:      iw.stream,
		canReattest: iw.canReattest,
		spiffeid:    iw.spiffeid,
		ctx:         iw.ctx,
	}
}

func (iw *InterceptorWrapper) setCustomStream(stream nodeattestorv1.NodeAttestor_AttestServer) {
	iw.stream = stream
	iw.ctx = stream.Context()
}
