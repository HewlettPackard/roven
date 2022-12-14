package hybridserver

import (
	"context"

	hclog "github.com/hashicorp/go-hclog"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
)

type ServerInterceptor interface {
	nodeattestorv1.NodeAttestor_AttestServer

	SetReq(req *nodeattestorv1.AttestRequest)
	CanReattest() []bool
	SpiffeID() string
	SetSpiffeID(spiffeID string)
	CombinedSelectors() []string
	Stream() nodeattestorv1.NodeAttestor_AttestServer
	NewInterceptor() ServerInterceptor
	setCustomStream(stream nodeattestorv1.NodeAttestor_AttestServer)
}

type HybridPluginServerInterceptor struct {
	nodeattestorv1.NodeAttestor_AttestServer

	stream            nodeattestorv1.NodeAttestor_AttestServer
	logger            hclog.Logger
	ctx               context.Context
	req               *nodeattestorv1.AttestRequest
	response          *nodeattestorv1.AttestResponse
	combinedSelectors []string
	spiffeID          string
	canReattest       []bool
}

func (m *HybridPluginServerInterceptor) NewInterceptor() ServerInterceptor {
	return &HybridPluginServerInterceptor{
		ctx:               m.ctx,
		stream:            m.stream,
		logger:            m.logger,
		req:               m.req,
		response:          m.response,
		combinedSelectors: m.combinedSelectors,
		spiffeID:          m.spiffeID,
		canReattest:       m.canReattest,
	}
}

func (m *HybridPluginServerInterceptor) Recv() (*nodeattestorv1.AttestRequest, error) {
	return m.req, nil
}

func (m *HybridPluginServerInterceptor) Send(resp *nodeattestorv1.AttestResponse) error {
	if x, ok := resp.GetResponse().(*nodeattestorv1.AttestResponse_AgentAttributes); ok {

		m.combinedSelectors = append(m.combinedSelectors, x.AgentAttributes.SelectorValues...)
		if len(m.spiffeID) == 0 {
			m.spiffeID = x.AgentAttributes.SpiffeId
		}

		m.canReattest = append(m.canReattest, x.AgentAttributes.CanReattest)
	}

	return nil
}

func (m *HybridPluginServerInterceptor) SetContext(ctx context.Context) {
	m.ctx = ctx
}

func (m *HybridPluginServerInterceptor) Context() context.Context {
	return m.ctx
}

func (m *HybridPluginServerInterceptor) SetLogger(logger hclog.Logger) {
	m.logger = logger
}

func (m *HybridPluginServerInterceptor) SetReq(req *nodeattestorv1.AttestRequest) {
	m.req = req
}

func (m *HybridPluginServerInterceptor) CanReattest() []bool {
	return m.canReattest
}

func (m *HybridPluginServerInterceptor) SpiffeID() string {
	return m.spiffeID
}

func (m *HybridPluginServerInterceptor) CombinedSelectors() []string {
	return m.combinedSelectors
}

func (m *HybridPluginServerInterceptor) Stream() nodeattestorv1.NodeAttestor_AttestServer {
	return m.stream
}

func (m *HybridPluginServerInterceptor) SetSpiffeID(spiffeID string) {
	m.spiffeID = spiffeID
}

func (m *HybridPluginServerInterceptor) setCustomStream(stream nodeattestorv1.NodeAttestor_AttestServer) {
	m.stream = stream
	m.ctx = stream.Context()
}

func NewServerInterceptor() ServerInterceptor {
	return &HybridPluginServerInterceptor{}
}
