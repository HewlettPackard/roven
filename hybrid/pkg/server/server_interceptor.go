package hybrid_server

import (
	"context"

	hclog "github.com/hashicorp/go-hclog"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
)

type ServerInterceptorInterface interface {
	Recv() (*nodeattestorv1.AttestRequest, error)
	Send(resp *nodeattestorv1.AttestResponse) error
	setCustomStream(stream nodeattestorv1.NodeAttestor_AttestServer)
	SetContext(ctx context.Context)
	Context() context.Context
	SetLogger(logger hclog.Logger)
	SetReq(req *nodeattestorv1.AttestRequest)
	CanReattest() []bool
	SpiffeID() string
	SetSpiffeID(spiffeID string)
	CombinedSelectors() []string
	Stream() nodeattestorv1.NodeAttestor_AttestServer
	ResetInterceptor()
	SpawnInterceptor() ServerInterceptorInterface
}

type HybridPluginServerInterceptor struct {
	ctx    context.Context
	stream nodeattestorv1.NodeAttestor_AttestServer
	nodeattestorv1.NodeAttestor_AttestServer
	logger            hclog.Logger
	req               *nodeattestorv1.AttestRequest
	Response          *nodeattestorv1.AttestResponse
	combinedSelectors []string
	spiffeID          string
	canReattest       []bool
}

func (m *HybridPluginServerInterceptor) ResetInterceptor() {
	m.ctx = nil
	m.stream = nil
	m.logger = nil
	m.req = nil
	m.Response = nil
	m.combinedSelectors = nil
	m.spiffeID = ""
	m.canReattest = nil
}

func (m *HybridPluginServerInterceptor) SpawnInterceptor() ServerInterceptorInterface {
	return &HybridPluginServerInterceptor{
		ctx:               m.ctx,
		stream:            m.stream,
		logger:            m.logger,
		req:               m.req,
		Response:          m.Response,
		combinedSelectors: m.combinedSelectors,
		spiffeID:          m.spiffeID,
		canReattest:       m.canReattest,
	}
}

func (m *HybridPluginServerInterceptor) Recv() (*nodeattestorv1.AttestRequest, error) {
	return m.req, nil // add error here
}

func (m *HybridPluginServerInterceptor) setCustomStream(stream nodeattestorv1.NodeAttestor_AttestServer) {
	m.stream = stream
}

func (m *HybridPluginServerInterceptor) Send(resp *nodeattestorv1.AttestResponse) error {
	switch x := resp.Response.(type) {
	case *nodeattestorv1.AttestResponse_AgentAttributes:
		m.combinedSelectors = append(m.combinedSelectors, x.AgentAttributes.SelectorValues...)
		if len(m.spiffeID) == 0 {
			m.spiffeID = x.AgentAttributes.SpiffeId
		}

		m.canReattest = append(m.canReattest, x.AgentAttributes.CanReattest)
	default:
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
