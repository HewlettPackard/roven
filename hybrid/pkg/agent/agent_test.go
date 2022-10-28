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
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/azuremsi"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/gcpiit"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/k8spsat"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/stretchr/testify/require"
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

// ------------------------------------------------------------------------------------------------------------------------

// 	// 	fake_psat := "eyJjbHVzdGVyIjoiaHlicmlkLW5vZGUtYXR0ZXN0b3JfZmFrZSIsInRva2VuIjoiZXlKaGJHY2lPaUpTVXpJMU5pSXNJbXRwWkNJNklqWXlOR0kyWkdZM05HWTRPVEl3WXpRNE5URm1OR0ZoTkdKbFpXSmxOVGczTWpWbE9EQTNPR1VpZlEuZXlKaGRXUWlPbHNpYzNCcGNtVXRjMlZ5ZG1WeUlsMHNJbVY0Y0NJNk1UWTJNemt3TURjM01Dd2lhV0YwSWpveE5qWXpPRGt6TlRjd0xDSnBjM01pT2lKb2RIUndjem92TDI5cFpHTXVaV3R6TG5WekxXVmhjM1F0TWk1aGJXRjZiMjVoZDNNdVkyOXRMMmxrTDBVeE9ESXdRelV4UmpOQk1EZzNNVEpFTWpkR09UbENNME5EUVVJMVFrTXdJaXdpYTNWaVpYSnVaWFJsY3k1cGJ5STZleUp1WVcxbGMzQmhZMlVpT2lKemNHbHlaU0lzSW5CdlpDSTZleUp1WVcxbElqb2ljM0JwY21VdFlXZGxiblF0WjIwM05uRWlMQ0oxYVdRaU9pSTJZbVZpWkdJd09TMWpNemczTFRRMllUSXRZVEEzTWkweU9UVmhaR1psTmpaa1pqQWlmU3dpYzJWeWRtbGpaV0ZqWTI5MWJuUWlPbnNpYm1GdFpTSTZJbk53YVhKbExXRm5aVzUwSWl3aWRXbGtJam9pWVRNeE4yTm1PVE10TUdKa05DMDBZemM0TFdGbFl6TXRaRFZoWWpFek4yTTRZems0SW4xOUxDSnVZbVlpT2pFMk5qTTRPVE0xTnpBc0luTjFZaUk2SW5ONWMzUmxiVHB6WlhKMmFXTmxZV05qYjNWdWREcHpjR2x5WlRwemNHbHlaUzFoWjJWdWRDSjkuR2pZN2lnQkhpUGVXUzZSWGwtS2Z0cGN0VFM4ekJrQ2lYRXNtZGdIUkk2YWNlTVBxS2F3ZDdvMU5ISGlJNHcxUHBBaHAwSGNpOFpHOG5xQjJwUDJTdy1aMWVuQzBwemZHUnB2RmJtRkFSZ0ZBSzA2N19kUk5SV2hSejFra2ZHMDFzQU9KcjFhb01sUHREMTZBTVB4RzZNSHhHU3BXV0tCT01PWmd2c1psQUw3WW1lelVEdXdTcUtXYy0tTHN5ZHhneDhTRGlwUlpwTzFqTmZ5Rl9fMnBadHd4cmw5VFBOY04wVS1DYk9lYktoWjFEODVsdzZvd2pURmpDVzRQcGxWQ2c1Qmx0VGtGajdnSndoMExtTEpveVZ0Wnltem9LZFBLQWhfZ3U5dFpUZ0dienNYMVJCX2xGNngxY000cmRocDVBb2dLZGNfT0NidGg3dUxnZTU2MGdRIn0="
// 	// 	fake_psat_decoded, _ := base64.StdEncoding.DecodeString(fake_psat)

// fake_aws := "eyJkb2N1bWVudCI6IntcbiAgXCJhY2NvdW50SWRcIiA6IFwiNzI4MTA5MDU4OTM5X1RFU1RFXCIsXG4gIFwiYXJjaGl0ZWN0dXJlXCIgOiBcIng4Nl82NFwiLFxuICBcImF2YWlsYWJpbGl0eVpvbmVcIiA6IFwidXMtZWFzdC0yYVwiLFxuICBcImJpbGxpbmdQcm9kdWN0c1wiIDogbnVsbCxcbiAgXCJkZXZwYXlQcm9kdWN0Q29kZXNcIiA6IG51bGwsXG4gIFwibWFya2V0cGxhY2VQcm9kdWN0Q29kZXNcIiA6IG51bGwsXG4gIFwiaW1hZ2VJZFwiIDogXCJhbWktMGUyOWY2Mzc2MThjZTlhODlcIixcbiAgXCJpbnN0YW5jZUlkXCIgOiBcImktMGRmYTViMTEyMjUxMDQ1MTZcIixcbiAgXCJpbnN0YW5jZVR5cGVcIiA6IFwibTUubGFyZ2VcIixcbiAgXCJrZXJuZWxJZFwiIDogbnVsbCxcbiAgXCJwZW5kaW5nVGltZVwiIDogXCIyMDIyLTA5LTIyVDAzOjIyOjIxWlwiLFxuICBcInByaXZhdGVJcFwiIDogXCIxOTIuMTY4Ljc3LjExNlwiLFxuICBcInJhbWRpc2tJZFwiIDogbnVsbCxcbiAgXCJyZWdpb25cIiA6IFwidXMtZWFzdC0yXCIsXG4gIFwidmVyc2lvblwiIDogXCIyMDE3LTA5LTMwXCJcbn0iLCJzaWduYXR1cmUiOiJlTzQrOTBQdU44YlphSUpqcEJlMS9tQXpQaHZTcnJoTEFUd1BGYU9Qeks1WlNVcHNiVk91SzJ0WGpNWWt4K29yYTdtY2FMMEc0NWxpXG5iWkxHVUllZStERi9ZWjgvNVJ1TmYxWjh5bis1ZTJBcUx2TmhJc0Y1SU9WWldrOHlEdmwvakJKQ2NXOEdhUmJsbGRXZE1vRGlDMk9BXG5xVnlSanlKQ1hVeVNOdTBKQURFPSJ9"
// fake_aws_decoded, _ := base64.StdEncoding.DecodeString(fake_aws)
