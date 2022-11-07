package hybrid_agent

import (
	"context"
	"encoding/json"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/hewlettpackard/hybrid/pkg/common"
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
	SendCombined(common.PluginMessageList) error
	SetPluginName(name string)
	GetMessage() common.PluginMessage
	SpawnInterceptor() AgentInterceptorInterface
}

type HybridPluginAgentInterceptor struct {
	ctx    context.Context
	stream nodeattestorv1.NodeAttestor_AidAttestationServer
	nodeattestorv1.NodeAttestor_AidAttestationServer
	logger     hclog.Logger
	payload    []byte
	pluginName string
}

func (m *HybridPluginAgentInterceptor) SetPluginName(name string) {
	m.pluginName = name
}

func (m *HybridPluginAgentInterceptor) GetMessage() common.PluginMessage {
	return common.PluginMessage{
		PluginName: m.pluginName,
		PluginData: m.payload,
	}
}

func (m *HybridPluginAgentInterceptor) setCustomStream(stream nodeattestorv1.NodeAttestor_AidAttestationServer) {
	m.stream = stream
}

func (m *HybridPluginAgentInterceptor) Recv() (*nodeattestorv1.Challenge, error) {
	return m.stream.Recv()
}

func (m *HybridPluginAgentInterceptor) Send(challenge *nodeattestorv1.PayloadOrChallengeResponse) error {
	m.payload = challenge.GetPayload()
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

func (m *HybridPluginAgentInterceptor) SendCombined(messageList common.PluginMessageList) error {
	jsonString, err := json.Marshal(messageList)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to marshal message list: %v", err)
	}
	payload := &nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{
			Payload: jsonString,
		},
	}
	return m.stream.Send(payload)
}

func (m *HybridPluginAgentInterceptor) SpawnInterceptor() AgentInterceptorInterface {
	return &HybridPluginAgentInterceptor{
		ctx:        m.ctx,
		stream:     m.stream,
		logger:     m.logger,
		payload:    m.payload,
		pluginName: m.pluginName,
	}
}
