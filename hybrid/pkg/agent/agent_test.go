package hybrid_agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/hewlettpackard/hybrid/pkg/common"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/awsiid"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

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

var pluginsStringEmptyData = `plugins {}`
var payloadOneData = `{"cluster":"hybrid-node-attestor_fake","token":"part1.part2.part3-part4-part5--part6-part7"}`
var payloadTwoData = `{"document":"{\n  \"accountId\" : \"123456789_TEST\",\n  \"architecture\" : \"x86_64\",\n  \"availabilityZone\" : \"us-east-2a\",\n  \"billingProducts\" : null,\n  \"devpayProductCodes\" : null,\n  \"marketplaceProductCodes\" : null,\n  \"imageId\" : \"ami-010203040506\",\n  \"instanceId\" : \"i-010203040506\",\n  \"instanceType\" : \"m5.large\",\n  \"kernelId\" : null,\n  \"pendingTime\" : \"2022-09-22T03:22:21Z\",\n  \"privateIp\" : \"192.168.77.116\",\n  \"ramdiskId\" : null,\n  \"region\" : \"us-east-2\",\n  \"version\" : \"2017-09-30\"\n}","signature":"eO4+90PuN8bZaIJjpBe1/mAzPhvSrrhLATwPFaOPzK5ZSUpsbVOuK2tXjMYkx+ora7mcaL0G45li\nbZLGUIee+DF/YZ8/5RuNf1Z8yn+5e2AqLvNhIsF5IOVZWk8yDvl/jBJCcW8GaRblldWdMoDiC2OA\nqVyRjyJCXUySNu0JADE="}`
var payloadThreeData = `{1,2,3,4,}`

// ------------------------------------------------------------------------------------------------------------------------

func TestMethodsThatParseHclConfig(t *testing.T) {
	interceptor := new(InterceptorWrapper)
	plugin := HybridPluginAgent{interceptor: interceptor}

	pluginAstNode, err := plugin.decodeStringAndTransformToAstNode(pluginsString)

	if len(pluginAstNode) != 2 {
		t.Error("Could not transform HCL string configuration.", err)
	}

	if pluginAstNode["aws_iid"] == nil || pluginAstNode["k8s_psat"] == nil {
		t.Error("Could access loaded plugins by index.", pluginAstNode)
	}

	pluginNames, pluginsData := plugin.parseReceivedData(pluginAstNode)

	if len(pluginNames) != 2 && pluginNames[0] != "k8s_psat" && pluginNames[1] != "aws_iid" {
		t.Error("Could not transform HCL received data into map and extract plugins names")
	}

	if len(pluginsData) != 2 &&
		pluginsData["aws_iid"] != "accountId = 728109058939" &&
		pluginsData["k8s_psat"] != `cluster = "hybrid-node-attestor"` {
		t.Error("Could not transform HCL received data into map and extract plugins names")
	}
}

func TestSupportedPluginsInitialization(t *testing.T) {
	interceptor := new(InterceptorWrapper)
	plugin := HybridPluginAgent{interceptor: interceptor}

	types, err := plugin.initPlugins([]string{"aws_iid", "k8s_psat", "azure_msi", "gcp_iit"})
	awsPluginType := awsiid.IIDAttestorPlugin{}

	if reflect.TypeOf(types[0].Plugin) != reflect.TypeOf(&awsPluginType) && err != nil {
		t.Error("Cannot init plugins properly")
	}

	types, err = plugin.initPlugins([]string{"aws_iid_test", "k8s_psat_test"})

	if len(types) > 0 {

		t.Error("Cannot init plugins properly")
	}

}

func TestHybridPluginConfiguration(t *testing.T) {
	interceptor := new(InterceptorWrapper)
	plugin := HybridPluginAgent{interceptor: interceptor}

	req := configv1.ConfigureRequest{HclConfiguration: pluginsString}

	_, errConfig := plugin.Configure(context.Background(), &req)

	if len(plugin.pluginList) == 0 || errConfig != nil {
		t.Error("Plugins used by Hybrid node attestor failed to start.")
	}

	req = configv1.ConfigureRequest{HclConfiguration: pluginsStringInvalidData}

	_, errConfig = plugin.Configure(context.Background(), &req)

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

func TestHybridPluginAgentInterceptorAndAidAttestation(t *testing.T) {
	combinedPayloads := []byte("")
	stream := StreamMock{CombinedPayloads: &combinedPayloads}
	interceptor := new(HybridPluginAgentInterceptor)

	interceptor.setCustomStream(&stream)
	customStream, _ := interceptor.Recv()
	if bytes.Compare([]byte("customStream"), customStream.Challenge) != 0 {
		t.Error("Could not set custom stream")
	}

	interceptor.SetContext(context.Background())
	customContext := interceptor.Context()
	if reflect.TypeOf(context.Background()) != reflect.TypeOf(customContext) {
		t.Error("Could not set interceptor context")
	}

	interceptor.SetLogger(hclog.Default())
	if reflect.TypeOf(hclog.Default()) != reflect.TypeOf(interceptor.logger) {
		t.Error("Could not set interceptor logger")
	}

	payloadEmpty := interceptor.payload

	payloadOne := nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{
			Payload: []byte(payloadOneData),
		},
	}
	interceptor.Send(&payloadOne)

	payloadTwo := nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{
			Payload: []byte(payloadTwoData),
		},
	}
	interceptor.Send(&payloadTwo)

	if payloadEmpty == nil {
		if len(interceptor.payload) > 0 && bytes.Compare(interceptor.payload[0], payloadOne.GetPayload()) != 0 {
			t.Error("Could not intercept Payload message")
		}
	}

	var combinedByteArray [][]byte
	combinedByteArray = append(combinedByteArray, []byte(payloadOneData))
	combinedByteArray = append(combinedByteArray, []byte(payloadTwoData))
	unmarshaledPayload, err_ := interceptor.unmarshalPayloadData(combinedByteArray)

	typeOf := new([]map[string]interface{})
	if reflect.TypeOf(&unmarshaledPayload) != reflect.TypeOf(typeOf) {
		t.Error("Failed to unmarshal intercepted payload data")
	}

	combined, _ := interceptor.combineAndMarshalUnmarshaledPayloads(unmarshaledPayload)

	typeOf_ := new([]byte)
	if reflect.TypeOf(&combined) != reflect.TypeOf(typeOf_) {
		t.Error("Failed to combined unmarshaled intercepted payload data")
	}

	stream.CombinedPayloads = &combined
	err := interceptor.SendCombined()
	if err != nil {
		t.Errorf("%v", err)
	}

	combinedByteArray = append(combinedByteArray, []byte(payloadThreeData))
	unmarshaledPayload, err_ = interceptor.unmarshalPayloadData(combinedByteArray)
	expectedError := status.Error(codes.InvalidArgument, "Failed to unmarshal data payload: invalid character '1' looking for beginning of object key string")
	if err_.Error() != expectedError.Error() {
		t.Error("Failed to unmarshal payload data")
	}

	pluginOne := new(FakePlugin)
	pluginTwo := new(FakePlugin)
	pluginList := []common.Types{
		common.Types{PluginName: "k8s_psat", Plugin: pluginOne},
		common.Types{PluginName: "aws_iid", Plugin: pluginTwo},
	}
	interceptorFake := new(InterceptorWrapper)
	hybridPlugin := HybridPluginAgent{pluginList: pluginList, logger: hclog.Default(), interceptor: interceptorFake}

	aidAttestation := hybridPlugin.AidAttestation(stream)
	if aidAttestation != nil {
		t.Error("AidAttestation of hybrid plugin fails")
	}

	interceptorFake.SetReturnError(true)

	aidAttestation = hybridPlugin.AidAttestation(stream)
	if aidAttestation == nil {
		t.Error("AidAttestation of hybrid plugin fails")
	}

	// ********** Log test

	hybridPlugin.SetLogger(hclog.Default())
	if hybridPlugin.logger != hclog.Default() {
		t.Error("Could not set logger for hybrid plugin")
	}

	expectedError = status.Error(codes.InvalidArgument, "Plugin initialization error")
	hybridPlugin.initStatus = expectedError
	aidAttestation = hybridPlugin.AidAttestation(stream)
	if aidAttestation.Error() != expectedError.Error() {
		t.Error("Plugin started without associated plugins configured")
	}
}

// ------------------------------------------------------------------------------------------------------------------------

type FakePlugin struct {
	returnError bool
}

func (f *FakePlugin) SetReturnError(state bool) {
	f.returnError = state
}

func (f *FakePlugin) AidAttestation(stream nodeattestorv1.NodeAttestor_AidAttestationServer) error {
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
	CombinedPayloads *[]byte
}

func (s StreamMock) Recv() (*nodeattestorv1.Challenge, error) {
	challenge := nodeattestorv1.Challenge{Challenge: []byte("customStream")}
	return &challenge, nil
}

func (s StreamMock) Send(challenge *nodeattestorv1.PayloadOrChallengeResponse) error {
	if bytes.Compare(*s.CombinedPayloads, challenge.GetPayload()) != 0 {
		return errors.New("Could not send intercepted payloads")
	}
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
