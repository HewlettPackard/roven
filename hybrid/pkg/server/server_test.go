package hybrid_server

import (
	"context"
	"fmt"
	"testing"

	hclog "github.com/hashicorp/go-hclog"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/awsiid"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/azuremsi"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/gcpiit"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/k8spsat"
	require "github.com/stretchr/testify/require"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

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
		aws_iida {
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
	require.Equal(t, "\n  clusters = \n    \"test-cluster\" = \n      service_account_allow_list = [\"production:spire-agent\"]\n    \n  \n", pluginsData["k8s_psat"], "k8s_psat plugin data was not extracted properly")
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

	// req := configv1.ConfigureRequest{CoreConfiguration: &coreSpireConfig, HclConfiguration: pluginsString}

	// _, errConfig := plugin.Configure(context.Background(), &req)
	// require.NoError(t, errConfig, "Error configuring plugin: %w", errConfig)
	// require.Len(t, plugin.pluginList, 2, "Plugins used by Hybrid node attestor failed to start.")
	// // if len(plugin.pluginList) == 0 || errConfig != nil {
	// // 	t.Error("Plugins used by Hybrid node attestor failed to start.")
	// // }

	req := configv1.ConfigureRequest{HclConfiguration: pluginsStringInvalidData}

	_, errConfig := plugin.Configure(context.Background(), &req)

	if errConfig == nil {
		t.Error("Plugins used by Hybrid node attestor failed to start.")
	}

	req = configv1.ConfigureRequest{HclConfiguration: pluginsStringEmptyData}

	_, errConfig = plugin.Configure(context.Background(), &req)

	error := status.Error(codes.FailedPrecondition, "No plugins supplied")

	if errConfig == nil || errConfig.Error() != error.Error() {
		t.Error("Plugins used by Hybrid node attestor failed to start.")
	}
}

func TestHybridPluginServerInterceptorAndAttest(t *testing.T) {
	combinedPayloads := []byte("")
	stream := StreamMock{CombinedPayloads: &combinedPayloads}
	interceptor := new(HybridPluginServerInterceptor)

	interceptor.setCustomStream(&stream)
	require.IsType(t, &StreamMock{}, interceptor.stream, "Could not set custom stream")

	err := interceptor.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				SelectorValues: []string{"test"},
				SpiffeId:       "spiffe://example.org/spire/agent/k8s_psat/test",
			},
		},
	})
	require.NoError(t, err, "Error sending response: %w", err)

	require.Equal(t, "spiffe://example.org/spire/agent/k8s_psat/test", interceptor.SpiffeID(), "Could not set custom response spiffeID")
	require.Equal(t, []string{"test"}, interceptor.CombinedSelectors(), "Could not set custom response selector values")

	interceptor.SetContext(context.WithValue(context.Background(), "testkey", "testval"))
	require.Equal(t, "testval", interceptor.Context().Value("testkey"), "Could not set interceptor context")

	interceptor.SetLogger(hclog.Default().Named("test_logger"))
	require.Equal(t, "test_logger", interceptor.logger.Name(), "Could not set interceptor logger")

	// payloadEmpty := interceptor.payload

	// payloadOne := nodeattestorv1.PayloadOrChallengeResponse{
	// 	Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{
	// 		Payload: []byte(payloadOneData),
	// 	},
	// }
	// interceptor.Send(&payloadOne)

	// payloadTwo := nodeattestorv1.PayloadOrChallengeResponse{
	// 	Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{
	// 		Payload: []byte(payloadTwoData),
	// 	},
	// }
	// interceptor.Send(&payloadTwo)

	// if payloadEmpty == nil {
	// 	if len(interceptor.payload) > 0 && bytes.Compare(interceptor.payload[0], payloadOne.GetPayload()) != 0 {
	// 		t.Error("Could not intercept Payload message")
	// 	}
	// }

	// var combinedByteArray [][]byte
	// combinedByteArray = append(combinedByteArray, []byte(payloadOneData))
	// combinedByteArray = append(combinedByteArray, []byte(payloadTwoData))
	// unmarshaledPayload, err_ := interceptor.unmarshalPayloadData(combinedByteArray)

	// typeOf := new([]map[string]interface{})
	// if reflect.TypeOf(&unmarshaledPayload) != reflect.TypeOf(typeOf) {
	// 	t.Error("Failed to unmarshal intercepted payload data")
	// }

	// combined, _ := interceptor.combineAndMarshalUnmarshaledPayloads(unmarshaledPayload)

	// typeOf_ := new([]byte)
	// if reflect.TypeOf(&combined) != reflect.TypeOf(typeOf_) {
	// 	t.Error("Failed to combined unmarshaled intercepted payload data")
	// }

	// stream.CombinedPayloads = &combined
	// err := interceptor.SendCombined()
	// if err != nil {
	// 	t.Errorf("%v", err)
	// }

	// combinedByteArray = append(combinedByteArray, []byte(payloadThreeData))
	// unmarshaledPayload, err_ = interceptor.unmarshalPayloadData(combinedByteArray)
	// expectedError := status.Error(codes.InvalidArgument, "failed to unmarshal data payload1: invalid character '1' looking for beginning of object key string")
	// if err_.Error() != expectedError.Error() {
	// 	t.Error("Failed to unmarshal payload data")
	// }

	pluginOne := new(FakePlugin)
	pluginTwo := new(FakePlugin)
	pluginList := []Types{
		Types{PluginName: "k8s_psat", Plugin: pluginOne},
		Types{PluginName: "aws_iid", Plugin: pluginTwo},
	}
	interceptorFake := new(InterceptorWrapper)
	hybridPlugin := HybridPluginServer{pluginList: pluginList, logger: hclog.Default(), interceptor: interceptorFake}

	// attest := hybridPlugin.Attest(stream)
	// if attest != nil {
	// 	t.Error("Attest of hybrid plugin fails")
	// }

	// interceptorFake.SetReturnError(true)

	// attest = hybridPlugin.Attest(stream)
	// if attest == nil {
	// 	t.Error("Attest of hybrid plugin fails")
	// }

	// ********** Log test

	hybridPlugin.SetLogger(hclog.Default())
	if hybridPlugin.logger != hclog.Default() {
		t.Error("Could not set logger for hybrid plugin")
	}

	// expectedError := status.Error(codes.InvalidArgument, "Plugin initialization error")
	// hybridPlugin.initStatus = expectedError
	// attest := hybridPlugin.Attest(stream)
	// if attest.Error() != expectedError.Error() {
	// 	t.Error("Plugin started without associated plugins configured")
	// }
}

// ------------------------------------------------------------------------------------------------------------------------

type FakePlugin struct {
	returnError bool
}

func (f *FakePlugin) SetReturnError(state bool) {
	f.returnError = state
}

func (f *FakePlugin) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {
	return nil
}

func (f *FakePlugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	fmt.Println("configure fake ", f.returnError)
	if f.returnError {
		return nil, status.Errorf(codes.Internal, "Error configuring one of the supplied plugins.")
	}

	return &configv1.ConfigureResponse{}, nil
}

// ----------------------------------------------------------------------------

type StreamMock struct {
	grpc.ServerStream
	CombinedPayloads *[]byte
	Response         *nodeattestorv1.AttestResponse
}

func (s StreamMock) Recv() (*nodeattestorv1.AttestRequest, error) {
	request := nodeattestorv1.AttestRequest{Request: &nodeattestorv1.AttestRequest_Payload{Payload: *s.CombinedPayloads}}
	return &request, nil
}

func (s StreamMock) Send(challenge *nodeattestorv1.AttestResponse) error {
	*s.Response = *challenge
	return nil
}

func (s StreamMock) Context() context.Context {
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
	returnError bool
	nodeattestorv1.NodeAttestor_AttestServer
}

func (iw *InterceptorWrapper) SetReturnError(state bool) {
	iw.returnError = state
}

func (iw *InterceptorWrapper) Recv() (*nodeattestorv1.AttestRequest, error) {
	return nil, nil
}

func (iw *InterceptorWrapper) Send(resp *nodeattestorv1.AttestResponse) error {
	return nil
}

func (iw *InterceptorWrapper) setCustomStream(stream nodeattestorv1.NodeAttestor_AttestServer) {

}

func (iw *InterceptorWrapper) SetContext(ctx context.Context) {

}

func (iw *InterceptorWrapper) Context() context.Context {
	return nil
}

func (iw *InterceptorWrapper) SetLogger(logger hclog.Logger) {

}

func (iw *InterceptorWrapper) SendCombined() error {
	if iw.returnError {
		return status.Error(codes.Internal, "Test Error")
	}

	return nil
}

func (iw *InterceptorWrapper) combineAndMarshalUnmarshaledPayloads(data []map[string]interface{}) ([]byte, error) {
	return nil, nil
}

func (iw *InterceptorWrapper) unmarshalPayloadData(payloadData [][]byte) ([]map[string]interface{}, error) {
	return nil, nil
}
func (iw *InterceptorWrapper) CanReattest() []bool {
	return nil
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
	return ""
}

func (iw *InterceptorWrapper) Stream() nodeattestorv1.NodeAttestor_AttestServer {
	return nil
}
