package hybrid_server

import (
	"context"

	hclog "github.com/hashicorp/go-hclog"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
)

type HybridPluginServerInterceptorInterface interface {
	Recv() (*nodeattestorv1.AttestRequest, error)
	Send(resp *nodeattestorv1.AttestResponse) error
	setCustomStream(stream nodeattestorv1.NodeAttestor_AttestServer)
	SetContext(ctx context.Context)
	Context() context.Context
	SetLogger(logger hclog.Logger)
	SetReq(req *nodeattestorv1.AttestRequest)
}

type HybridPluginServerInterceptor struct {
	ctx    context.Context
	stream nodeattestorv1.NodeAttestor_AttestServer
	nodeattestorv1.NodeAttestor_AttestServer
	logger            hclog.Logger
	req               *nodeattestorv1.AttestRequest
	Response          *nodeattestorv1.AttestResponse
	CombinedSelectors []string
	SpiffeID          string
	CanReattest       []bool
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
		m.CombinedSelectors = append(m.CombinedSelectors, x.AgentAttributes.SelectorValues...)
		if len(m.SpiffeID) == 0 {
			m.SpiffeID = x.AgentAttributes.SpiffeId
		}

		m.CanReattest = append(m.CanReattest, x.AgentAttributes.CanReattest)
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
