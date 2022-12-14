package hybridagent

import (
	"encoding/json"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hewlettpackard/hybrid/pkg/common"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"

	"github.com/stretchr/testify/require"
)

func TestHybridPluginAgentInterceptor(t *testing.T) {
	emptyPayload := []byte("")
	stream := StreamMock{Payload: &emptyPayload}
	interceptor := new(HybridPluginAgentInterceptor)

	interceptor.setCustomStream(&stream)
	customStream, err := interceptor.Recv()
	require.Equal(t, []byte("customStream"), customStream.Challenge, "Could not set custom stream on interceptor")
	require.NoError(t, err)
	customContext := interceptor.Context()
	require.Equal(t, "testval", customContext.Value("testkey"), "Could not set interceptor context")

	interceptor.SetLogger(hclog.Default().Named("test_logger"))
	require.Equal(t, "test_logger", interceptor.logger.Name(), "Could not set interceptor logger")

	payloadOne := nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{
			Payload: []byte(k8sPayloadData),
		},
	}
	interceptor.Send(&payloadOne)
	require.Equal(t, []byte(k8sPayloadData), interceptor.payload, "Could not set payload on interceptor")

	payloadTwo := nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{
			Payload: []byte(awsPayloadData),
		},
	}
	interceptor.Send(&payloadTwo)
	require.Equal(t, []byte(awsPayloadData), interceptor.payload, "Could not replace payload on interceptor")

	interceptor.payload = nil
	interceptorOne := NewAgentInterceptor()
	interceptorOne.SetPluginName("test_pluginOne")
	interceptorOne.Send(&payloadOne)

	interceptorTwo := NewAgentInterceptor()
	interceptorTwo.SetPluginName("test_pluginTwo")
	interceptorTwo.Send(&payloadTwo)
	var messageList common.PluginMessageList

	message1 := interceptorOne.GetMessage()
	require.Equal(t, []byte(k8sPayloadData), message1.PluginData, "Could not get message from interceptor")
	require.Equal(t, "test_pluginOne", message1.PluginName, "Could not get plugin name from interceptor")
	message2 := interceptorTwo.GetMessage()
	require.Equal(t, []byte(awsPayloadData), message2.PluginData, "Could not get message from interceptor")
	require.Equal(t, "test_pluginTwo", message2.PluginName, "Could not get plugin name from interceptor")
	messageList.Messages = append(messageList.Messages, message1)
	messageList.Messages = append(messageList.Messages, message2)
	agent := New()
	agent.SendCombined(messageList, stream)

	jsonMessage, err := json.Marshal(messageList)
	require.NoError(t, err)
	require.Equal(t, &jsonMessage, stream.Payload, "Could not send combined message list to stream")
}
