package hybrid_agent

import (
	"bytes"
	"context"
	"reflect"
	"strings"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/printer"

	"github.com/hewlettpackard/hybrid/pkg/common"
	agentstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/agentstore/v1"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/awsiid"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/azuremsi"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/gcpiit"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/k8spsat"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type HybridPluginAgent struct {
	pluginList []common.Types
	agentstorev1.UnimplementedAgentStoreServer
	nodeattestorv1.UnsafeNodeAttestorServer
	configv1.UnsafeConfigServer
	logger      hclog.Logger
	interceptor AgentInterceptorInterface
	initStatus  error
}

func New() *HybridPluginAgent {
	interceptor := new(HybridPluginAgentInterceptor)
	return &HybridPluginAgent{interceptor: interceptor}
}

func (p *HybridPluginAgent) SetLogger(logger hclog.Logger) {
	p.logger = logger

}
func (p *HybridPluginAgent) AidAttestation(stream nodeattestorv1.NodeAttestor_AidAttestationServer) error {
	if len(p.pluginList) == 0 || p.initStatus != nil {
		return status.Errorf(codes.InvalidArgument, "Plugin initialization error")
	}

	p.interceptor.setCustomStream(stream)
	p.interceptor.SetContext(stream.Context())
	p.interceptor.SetLogger(p.logger)

	interceptors := []AgentInterceptorInterface{}

	for i := 0; i < len(p.pluginList); i++ {
		var newInterceptor AgentInterceptorInterface = p.interceptor.SpawnInterceptor()
		newInterceptor.SetPluginName(p.pluginList[i].PluginName)
		interceptors = append(interceptors, newInterceptor)

		elem := reflect.ValueOf(p.pluginList[i].Plugin)
		result := elem.MethodByName("AidAttestation").Call([]reflect.Value{reflect.ValueOf(newInterceptor)})
		err := result[0].Interface()
		if err != nil {
			return status.Errorf(codes.Internal, "An error ocurred when during AidAttestation.")
		}
	}

	combinedMessage := common.PluginMessageList{}
	for i := 0; i < len(interceptors); i++ {
		combinedMessage.Messages = append(combinedMessage.Messages, interceptors[i].GetMessage())
	}

	return p.interceptor.SendCombined(combinedMessage)
}

func (p *HybridPluginAgent) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
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
			return &configv1.ConfigureResponse{}, status.Errorf(codes.Internal, "Error configuring one of the supplied plugins.")
		}
	}

	return &configv1.ConfigureResponse{}, nil
}

func (p *HybridPluginAgent) decodeStringAndTransformToAstNode(hclData string) (common.Generics, error) {
	var genericData common.GenericPluginSuper
	if err := hcl.Decode(&genericData, hclData); err != nil {
		return nil, err
	}

	var data bytes.Buffer
	printer.DefaultConfig.Fprint(&data, genericData.Plugins)

	var astNodeData common.Generics

	if err := hcl.Decode(&astNodeData, data.String()); err != nil {
		return nil, err
	}

	return astNodeData, nil
}

func (p *HybridPluginAgent) parseReceivedData(data common.Generics) ([]string, map[string]string) {
	str := map[string]string{}
	plugins := []string{}
	for key := range data {
		var data_ bytes.Buffer
		printer.DefaultConfig.Fprint(&data_, data[key])
		str[key] = strings.Replace(strings.Replace(data_.String(), "{", "", -1), "}", "", -1)
		plugins = append(plugins, key)
	}
	return plugins, str
}

func (p *HybridPluginAgent) initPlugins(pluginList []string) ([]common.Types, error) {
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
