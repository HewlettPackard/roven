package hybrid_server

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/printer"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/hewlettpackard/hybrid/pkg/common"
	agentstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/agentstore/v1"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/server/hostservice/agentstore"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/awsiid"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/azuremsi"
	nodeattestorbase "github.com/spiffe/spire/pkg/server/plugin/nodeattestor/base"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/gcpiit"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/k8spsat"
)

var (
	_ pluginsdk.NeedsHostServices = (*HybridPluginServer)(nil)
)

type HybridPluginServer struct {
	pluginList []common.Types
	nodeattestorbase.Base
	agentstorev1.UnimplementedAgentStoreServer
	nodeattestorv1.UnimplementedNodeAttestorServer
	configv1.UnsafeConfigServer

	logger      hclog.Logger
	store       agentstorev1.AgentStoreServiceClient
	broker      pluginsdk.ServiceBroker
	interceptor ServerInterceptorInterface
	initStatus  error
}

func New() *HybridPluginServer {
	interceptor := new(HybridPluginServerInterceptor)
	return &HybridPluginServer{interceptor: interceptor}
}

func (p *HybridPluginServer) SetLogger(logger hclog.Logger) {
	p.logger = logger
}

func (p *HybridPluginServer) BrokerHostServices(broker pluginsdk.ServiceBroker) error {
	p.broker = broker

	return nil
}

func (p *HybridPluginServer) setBrokerHostServices() error {
	if !p.broker.BrokerClient(&p.store) {
		return errors.New("Agent store service required")
	}

	for i := 0; i < len(p.pluginList); i++ {
		elem := reflect.ValueOf(p.pluginList[i].Plugin)
		method := elem.MethodByName("BrokerHostServices")
		if method.IsValid() {
			err := elem.MethodByName("BrokerHostServices").Call([]reflect.Value{reflect.ValueOf(p.broker)})
			p.logger.Debug(err[0].String())
		}
	}

	return nil
}

func (p *HybridPluginServer) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {
	req, err := stream.Recv()
	if err != nil {
		return err
	}

	p.interceptor.setCustomStream(stream)
	p.interceptor.SetContext(stream.Context())
	p.interceptor.SetLogger(p.logger)
	p.interceptor.SetReq(req)

	for i := 0; i < len(p.pluginList); i++ {
		elem := reflect.ValueOf(p.pluginList[i].Plugin)
		elem.MethodByName("SetLogger").Call([]reflect.Value{reflect.ValueOf(p.logger)})
		result := elem.MethodByName("Attest").Call([]reflect.Value{reflect.ValueOf(p.interceptor)})
		if result[0].Interface() != nil {
			callError, _ := status.FromError(result[0].Interface().(error))
			return status.Errorf(codes.Internal, callError.Message())
		}
	}

	return p.SendResponse()
}

func (p *HybridPluginServer) SendResponse() error {
	canReattest := true
	for _, n := range p.interceptor.CanReattest() {
		if !n {
			attested, err := agentstore.IsAttested(context.Background(), p.store, p.interceptor.SpiffeID())
			canReattest = false
			switch {
			case err != nil:
				return err
			case attested:
				return status.Error(codes.PermissionDenied, "attestation data has already been used to attest an agent")
			default:
			}
		}
	}

	return p.interceptor.Stream().Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				CanReattest:    canReattest,
				SpiffeId:       p.interceptor.SpiffeID(),
				SelectorValues: p.interceptor.CombinedSelectors(),
			},
		},
	})
}

func (p *HybridPluginServer) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	pluginData, _ := p.decodeStringAndTransformToAstNode(req.HclConfiguration)

	pluginNames, pluginsData := p.parseReceivedData(pluginData)

	p.pluginList, p.initStatus = p.initPlugins(pluginNames)

	if len(p.pluginList) == 0 || p.initStatus != nil {
		return nil, p.initStatus
	}

	for i := 0; i < len(p.pluginList); i++ {
		elem := reflect.ValueOf(p.pluginList[i].Plugin)
		req.HclConfiguration = pluginsData[p.pluginList[i].PluginName]

		result := elem.MethodByName("Configure").Call([]reflect.Value{reflect.ValueOf(ctx), reflect.ValueOf(req)})
		err := result[1]

		if !err.IsNil() {
			return &configv1.ConfigureResponse{}, status.Errorf(codes.Internal, "Error configuring one of the supplied plugins(%s): %s", p.pluginList[i].PluginName, err.Interface().(error))
		}
	}

	p.setBrokerHostServices()

	return &configv1.ConfigureResponse{}, nil
}

func (p *HybridPluginServer) decodeStringAndTransformToAstNode(hclData string) (common.Generics, error) {
	var genericData common.GenericPluginSuper
	if err := hcl.Decode(&genericData, hclData); err != nil {
	}

	var data bytes.Buffer
	printer.DefaultConfig.Fprint(&data, genericData.Plugins)

	var astNodeData common.Generics

	if err := hcl.Decode(&astNodeData, data.String()); err != nil {
	}

	return astNodeData, nil
}

func (p *HybridPluginServer) parseReceivedData(data common.Generics) ([]string, map[string]string) {

	str := map[string]string{}
	plugins := []string{}
	for key := range data {
		var data_ bytes.Buffer
		printer.DefaultConfig.Fprint(&data_, data[key])
		result := strings.Replace(data_.String(), "{", "", 1)
		result = reverse(strings.Replace(reverse(result), "}", reverse(""), 1))
		str[key] = result
		plugins = append(plugins, key)
	}

	return plugins, str
}

func reverse(s string) (result string) {
	for _, v := range s {
		result = string(v) + result
	}
	return
}

func (p *HybridPluginServer) initPlugins(pluginList []string) ([]common.Types, error) {
	attestors := make([]common.Types, 0)

	for i := 0; i < len(pluginList); i++ {
		var plugin common.Types
		switch pluginList[i] {
		case "aws_iid":
			plugin.PluginName = "aws_iid"
			plugin.Plugin = awsiid.New()
		case "k8s_psat":
			plugin.PluginName = "k8s_psat"
			plugin.Plugin = k8spsat.New()
		case "azure_msi":
			plugin.PluginName = "azure_msi"
			plugin.Plugin = azuremsi.New()
		case "gcp_iit":
			plugin.PluginName = "gcp_iit"
			plugin.Plugin = gcpiit.New()
		default:
			plugin.PluginName = ""
			plugin.Plugin = nil
		}

		attestors = append(attestors, plugin)
	}

	for i := 0; i < len(attestors); i++ {
		if attestors[i].Plugin == nil {
			return nil, status.Error(codes.FailedPrecondition, "Some of the supplied plugins are not supported or are invalid")
		}
	}

	if len(attestors) == 0 {
		return nil, status.Error(codes.FailedPrecondition, "No plugins supplied")
	}

	return attestors, nil
}
