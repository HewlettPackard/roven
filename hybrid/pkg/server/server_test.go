// package hybrid_server

// import (
// 	"bytes"
// 	"context"
// 	"errors"
// 	"reflect"
// 	"strings"
// 	"sync"

// 	hclog "github.com/hashicorp/go-hclog"
// 	"github.com/hashicorp/hcl"
// 	"github.com/hashicorp/hcl/hcl/ast"
// 	"github.com/hashicorp/hcl/hcl/printer"
// 	"github.com/spiffe/spire-plugin-sdk/pluginmain"
// 	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
// 	"google.golang.org/grpc/codes"
// 	"google.golang.org/grpc/status"

// 	agentstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/agentstore/v1"
// 	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
// 	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
// 	"github.com/spiffe/spire/pkg/server/hostservice/agentstore"
// 	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/awsiid"
// 	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/azuremsi"
// 	nodeattestorbase "github.com/spiffe/spire/pkg/server/plugin/nodeattestor/base"
// 	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/gcpiit"
// 	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/k8spsat"
// )

// var (
// 	_ pluginsdk.NeedsHostServices = (*HybridPluginServer)(nil)
// )

// type Types struct {
// 	PluginName string
// 	Plugin     interface{}
// }

// type GenericPluginSuper struct {
// 	Plugins ast.Node `hcl:"plugins"`
// }

// type Generics map[string]ast.Node

// type HybridPluginServer struct {
// 	pluginList []Types
// 	nodeattestorbase.Base
// 	agentstorev1.UnimplementedAgentStoreServer
// 	nodeattestorv1.UnsafeNodeAttestorServer
// 	configv1.UnsafeConfigServer
// 	log    hclog.Logger
// 	store  agentstorev1.AgentStoreServiceClient
// 	mtx    sync.RWMutex
// 	broker pluginsdk.ServiceBroker
// }

// func (p *HybridPluginServer) SetLogger(logger hclog.Logger) {
// 	p.log = logger
// }

// func (p *HybridPluginServer) BrokerHostServices(broker pluginsdk.ServiceBroker) error {
// 	p.broker = broker

// 	return nil
// }

// func (p *HybridPluginServer) setBrokerHostServices() error {
// 	if !p.broker.BrokerClient(&p.store) {
// 		return errors.New("Agent store service required")
// 	}

// 	for i := 0; i < len(p.pluginList); i++ {
// 		elem := reflect.ValueOf(p.pluginList[i].Plugin)
// 		method := elem.MethodByName("BrokerHostServices")
// 		if method.IsValid() {
// 			err := elem.MethodByName("BrokerHostServices").Call([]reflect.Value{reflect.ValueOf(p.broker)})
// 			p.log.Debug(err[0].String())
// 		}
// 	}

// 	return nil
// }

// type HybridPluginServerInterceptorInterface interface {
// 	Recv() (*nodeattestorv1.AttestRequest, error)
// 	Send(resp *nodeattestorv1.AttestResponse) error
// 	setCustomStream(stream nodeattestorv1.NodeAttestor_AttestServer)
// 	SetContext(ctx context.Context)
// 	Context() context.Context
// 	SetLogger(logger hclog.Logger)
// 	SetReq(req *nodeattestorv1.AttestRequest)
// }

// type HybridPluginServerInterceptor struct {
// 	ctx    context.Context
// 	stream nodeattestorv1.NodeAttestor_AttestServer
// 	nodeattestorv1.NodeAttestor_AttestServer
// 	logger            hclog.Logger
// 	req               *nodeattestorv1.AttestRequest
// 	Response          *nodeattestorv1.AttestResponse
// 	CombinedSelectors []string
// 	SpiffeID          string
// 	CanReattest       []bool
// }

// func (m *HybridPluginServerInterceptor) Recv() (*nodeattestorv1.AttestRequest, error) {
// 	return m.req, nil // add error here
// }

// func (m *HybridPluginServerInterceptor) setCustomStream(stream nodeattestorv1.NodeAttestor_AttestServer) {
// 	m.stream = stream
// }

// func (m *HybridPluginServerInterceptor) Send(resp *nodeattestorv1.AttestResponse) error {
// 	switch x := resp.Response.(type) {
// 	case *nodeattestorv1.AttestResponse_AgentAttributes:
// 		m.CombinedSelectors = append(m.CombinedSelectors, x.AgentAttributes.SelectorValues...)
// 		if len(m.SpiffeID) == 0 {
// 			m.SpiffeID = x.AgentAttributes.SpiffeId
// 		}

// 		m.CanReattest = append(m.CanReattest, x.AgentAttributes.CanReattest)
// 	default:
// 	}

// 	return nil
// }

// func (m *HybridPluginServerInterceptor) SetContext(ctx context.Context) {
// 	m.ctx = ctx
// }

// func (m *HybridPluginServerInterceptor) Context() context.Context {
// 	return m.ctx
// }

// func (m *HybridPluginServerInterceptor) SetLogger(logger hclog.Logger) {
// 	m.logger = logger
// }

// func (m *HybridPluginServerInterceptor) SetReq(req *nodeattestorv1.AttestRequest) {
// 	m.req = req
// }

// func (p *HybridPluginServer) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {
// 	req, err := stream.Recv()
// 	if err != nil {
// 		return err
// 	}

// 	interceptor := new(HybridPluginServerInterceptor)
// 	interceptor.setCustomStream(stream)
// 	interceptor.SetLogger(p.log)
// 	interceptor.SetReq(req)

// 	for i := 0; i < len(p.pluginList); i++ {
// 		interceptor.SetContext(context.Background())
// 		elem := reflect.ValueOf(p.pluginList[i].Plugin)
// 		elem.MethodByName("SetLogger").Call([]reflect.Value{reflect.ValueOf(p.log)})
// 		result := elem.MethodByName("Attest").Call([]reflect.Value{reflect.ValueOf(interceptor)})
// 		if result[0].Interface() != nil {
// 			callError, _ := status.FromError(result[0].Interface().(error))
// 			return status.Errorf(codes.Internal, callError.Message())
// 		}
// 	}

// 	canReattest := true
// 	for _, n := range interceptor.CanReattest {
// 		if !n {
// 			attested, err := agentstore.IsAttested(context.Background(), p.store, interceptor.SpiffeID)
// 			canReattest = false
// 			switch {
// 			case err != nil:
// 				return err
// 			case attested:
// 				return status.Error(codes.PermissionDenied, "attestation data has already been used to attest an agent")
// 			default:
// 			}
// 		}
// 	}

// 	return stream.Send(&nodeattestorv1.AttestResponse{
// 		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
// 			AgentAttributes: &nodeattestorv1.AgentAttributes{
// 				CanReattest:    canReattest,
// 				SpiffeId:       interceptor.SpiffeID,
// 				SelectorValues: interceptor.CombinedSelectors,
// 			},
// 		},
// 	})
// }

// func (p *HybridPluginServer) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
// 	pluginData, _ := p.decodeStringAndTransformToAstNode(req.HclConfiguration)

// 	plugins, str := p.parseReceivedData(pluginData)
// 	var initStatus error
// 	p.pluginList, initStatus = initPlugins(plugins)

// 	if len(p.pluginList) == 0 || initStatus != nil {
// 		return nil, initStatus
// 	}
// 	for i := 0; i < len(p.pluginList); i++ {
// 		elem := reflect.ValueOf(p.pluginList[i].Plugin)
// 		req.HclConfiguration = str[p.pluginList[i].PluginName]
// 		result := elem.MethodByName("Configure").Call([]reflect.Value{reflect.ValueOf(ctx), reflect.ValueOf(req)})
// 		err := result[1]

// 		if !err.IsNil() {
// 			return &configv1.ConfigureResponse{}, status.Errorf(codes.Internal, result[1].String())
// 		}
// 	}

// 	p.setBrokerHostServices()

// 	return &configv1.ConfigureResponse{}, nil
// }

// func (p *HybridPluginServer) decodeStringAndTransformToAstNode(hclData string) (Generics, error) {
// 	var genericData GenericPluginSuper
// 	if err := hcl.Decode(&genericData, hclData); err != nil {
// 	}

// 	var data bytes.Buffer
// 	printer.DefaultConfig.Fprint(&data, genericData.Plugins)

// 	var astNodeData Generics

// 	if err := hcl.Decode(&astNodeData, data.String()); err != nil {
// 	}

// 	return astNodeData, nil
// }

// func (p *HybridPluginServer) parseReceivedData(data Generics) ([]string, map[string]string) {

// 	str := map[string]string{}
// 	plugins := []string{}
// 	for key := range data {
// 		var data_ bytes.Buffer
// 		printer.DefaultConfig.Fprint(&data_, data[key])
// 		result := strings.Replace(data_.String(), "{", "", 1)
// 		result = reverse(strings.Replace(reverse(result), "}", reverse(""), 1))
// 		str[key] = result
// 		plugins = append(plugins, key)
// 	}

// 	return plugins, str
// }

// func reverse(s string) (result string) {
// 	for _, v := range s {
// 		result = string(v) + result
// 	}
// 	return
// }

// func initPlugins(pluginList []string) ([]Types, error) {
// 	attestors := make([]Types, 0)

// 	for i := 0; i < len(pluginList); i++ {
// 		var plugin Types
// 		switch pluginList[i] {
// 		case "aws_iid":
// 			plugin.PluginName = "aws_iid"
// 			plugin.Plugin = awsiid.New()
// 		case "k8s_psat":
// 			plugin.PluginName = "k8s_psat"
// 			plugin.Plugin = k8spsat.New()
// 		case "azure_msi":
// 			plugin.PluginName = "azure_msi"
// 			plugin.Plugin = azuremsi.New()
// 		case "gcp_iit":
// 			plugin.PluginName = "gcp_iit"
// 			plugin.Plugin = gcpiit.New()
// 			// case "tpm_devid":
// 			// 	plugin.PluginName = "tpm_devid"
// 			// 	plugin.Plugin = tpmdevid.New()
// 			// case "k8s_sat":
// 			// 	plugin.PluginName = "k8s_sat"
// 			// 	plugin.Plugin = k8ssat.New()
// 			// case "sshpop":
// 			// 	plugin.PluginName = "sshpop"
// 			// 	plugin.Plugin = sshpop.New()
// 			// case "x509pop":
// 			// 	plugin.PluginName = "x509pop"
// 			// 	plugin.Plugin = x509pop.New()
// 		default:
// 			plugin.PluginName = ""
// 			plugin.Plugin = nil
// 		}

// 		attestors = append(attestors, plugin)
// 	}

// 	for i := 0; i < len(attestors); i++ {
// 		if attestors[i].Plugin == nil {
// 			return nil, status.Error(codes.FailedPrecondition, "Some of the supplied plugins are not supported or are invalid")
// 		}
// 	}

// 	if len(attestors) == 0 {
// 		return nil, status.Error(codes.FailedPrecondition, "No plugins supplied")
// 	}

// 	return attestors, nil
// }

// func main() {
// 	testar := HybridPluginServer{}

// 	pluginmain.Serve(
// 		nodeattestorv1.NodeAttestorPluginServer(&testar),
// 		configv1.ConfigServiceServer(&testar),
// 	)
// }
