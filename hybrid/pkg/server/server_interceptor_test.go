package hybridserver

import (
	"context"
	"testing"

	hclog "github.com/hashicorp/go-hclog"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	"github.com/stretchr/testify/require"
)

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
	require.NoError(t, errConfig)
	require.Equal(t, []byte("testchallenge"), gotReq.GetChallengeResponse(), "Could not set interceptor request")

	var newInterceptor ServerInterceptor = interceptor.NewInterceptor()
	require.IsType(t, &HybridPluginServerInterceptor{}, newInterceptor, "Spawned interceptor is not of type HybridPluginServerInterceptor")
	require.Equal(t, interceptor, newInterceptor, "Spawned interceptor is not equal to original interceptor")

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
	require.NoError(t, err)

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
	require.NoError(t, err)
	require.Equal(t, "spiffe://example.org/spire/agent/k8s_psat/test", interceptor.SpiffeID(), "SpiffeID was overwritten on second response: %q", interceptor.SpiffeID())
	require.Equal(t, []string{"test", "test2", "test3", "test4"}, interceptor.CombinedSelectors(), "Selector values not appended properly on second response: %q", interceptor.CombinedSelectors())
	require.Equal(t, []bool{false, true}, interceptor.CanReattest(), "CanReattest was not set properly on second response: %t", interceptor.CanReattest())

}
