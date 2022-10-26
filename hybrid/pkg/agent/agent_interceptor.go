package hybrid_agent

import (
	"context"
	"encoding/json"

	hclog "github.com/hashicorp/go-hclog"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AgentInterceptorInterface interface {
	Recv() (*nodeattestorv1.Challenge, error)
	Send(challenge *nodeattestorv1.PayloadOrChallengeResponse) error
	setCustomStream(stream nodeattestorv1.NodeAttestor_AidAttestationServer)
	SetContext(ctx context.Context)
	Context() context.Context
	SetLogger(logger hclog.Logger)
	SendCombined() error
}

type HybridPluginAgentInterceptor struct {
	ctx    context.Context
	stream nodeattestorv1.NodeAttestor_AidAttestationServer
	nodeattestorv1.NodeAttestor_AidAttestationServer
	logger  hclog.Logger
	payload [][]byte
}

func (m *HybridPluginAgentInterceptor) setCustomStream(stream nodeattestorv1.NodeAttestor_AidAttestationServer) {
	m.stream = stream
}

func (m *HybridPluginAgentInterceptor) Recv() (*nodeattestorv1.Challenge, error) {
	return m.stream.Recv()
}

func (m *HybridPluginAgentInterceptor) Send(challenge *nodeattestorv1.PayloadOrChallengeResponse) error {
	payload := challenge.GetPayload()
	m.payload = append(m.payload, payload)

	return nil
}

func (m *HybridPluginAgentInterceptor) SetContext(ctx context.Context) {
	m.ctx = ctx
}

func (m *HybridPluginAgentInterceptor) Context() context.Context {
	return m.ctx
}

func (m *HybridPluginAgentInterceptor) SetLogger(logger hclog.Logger) {
	m.logger = logger
}

func (m *HybridPluginAgentInterceptor) SendCombined() error {
	data, _ := m.unmarshalPayloadData(m.payload)

	combinedPayloads, _ := m.combineAndMarshalUnmarshaledPayloads(data)

	payload := &nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{
			Payload: []byte(combinedPayloads),
		},
	}

	return m.stream.Send(payload)
}

func (m *HybridPluginAgentInterceptor) combineAndMarshalUnmarshaledPayloads(data []map[string]interface{}) ([]byte, error) {
	jsonData := data[0]
	for i := 1; i < len(data); i++ {
		for k, v := range data[i] {
			jsonData[k] = v
		}
	}

	return json.Marshal(jsonData)
}

func (m *HybridPluginAgentInterceptor) unmarshalPayloadData(payloadData [][]byte) ([]map[string]interface{}, error) {
	var data []map[string]interface{}

	var jsonData map[string]interface{}

	for i := 0; i < len(payloadData); i++ {
		jsonData = nil
		if err := json.Unmarshal(payloadData[i], &jsonData); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "Failed to unmarshal data payload: %v", err)
		}
		data = append(data, jsonData)
	}

	return data, nil
}
