package hybridagent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"

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
	agentstorev1.UnimplementedAgentStoreServer
	nodeattestorv1.UnsafeNodeAttestorServer
	configv1.UnsafeConfigServer

	pluginList []common.Types
	logger     hclog.Logger
	initStatus error
	mu         sync.RWMutex
}

func New() *HybridPluginAgent {
	return &HybridPluginAgent{}
}

func (p *HybridPluginAgent) SetLogger(logger hclog.Logger) {
	p.logger = logger
}

func (p *HybridPluginAgent) AidAttestation(stream nodeattestorv1.NodeAttestor_AidAttestationServer) error {
	if len(p.pluginList) == 0 || p.initStatus != nil {
		return status.Errorf(codes.FailedPrecondition, "plugin initialization error")
	}

	interceptors := make([]AgentInterceptor, 0, len(p.pluginList))

	for _, plugin := range p.pluginList {
		newInterceptor := NewAgentInterceptor()
		newInterceptor.SetPluginName(plugin.PluginName)
		newInterceptor.setCustomStream(stream)
		newInterceptor.SetLogger(p.logger)
		interceptors = append(interceptors, newInterceptor)

		elem := reflect.ValueOf(plugin.Plugin)
		result := elem.MethodByName("AidAttestation").Call([]reflect.Value{reflect.ValueOf(newInterceptor)})

		if err := result[0].Interface(); err != nil {
			errorString := fmt.Sprintf("%v", err)
			return status.Errorf(codes.Internal, "an error occurred during AidAttestation of the %v plugin. The error was %v", plugin.PluginName, errorString)
		}
	}

	combinedMessage := common.PluginMessageList{}
	for _, interceptor := range interceptors {
		combinedMessage.Messages = append(combinedMessage.Messages, interceptor.GetMessage())
	}

	return p.SendCombined(combinedMessage, stream)
}

func (m *HybridPluginAgent) SendCombined(messageList common.PluginMessageList, stream nodeattestorv1.NodeAttestor_AidAttestationServer) error {
	jsonString, err := json.Marshal(messageList)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to marshal message list: %v", err)
	}
	payload := &nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{
			Payload: jsonString,
		},
	}
	return stream.Send(payload)
}

func (p *HybridPluginAgent) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	pluginData, configError := p.decodeStringAndTransformToAstNode(req.HclConfiguration)

	if configError != nil {
		return nil, status.Errorf(codes.Internal, "error configuring plugin. %v", configError)
	}

	pluginNames, pluginsData := p.parseReceivedData(pluginData)

	pluginList, initStatus := p.initPlugins(pluginNames)
	p.pluginList = pluginList
	p.initStatus = initStatus

	if len(p.pluginList) == 0 || p.initStatus != nil {
		return nil, p.initStatus
	}

	for _, plugin := range p.pluginList {
		elem := reflect.ValueOf(plugin.Plugin)
		req.HclConfiguration = pluginsData[plugin.PluginName]

		methodCall := elem.MethodByName("Configure")

		if methodCall.Kind() == 0 {
			return nil, status.Errorf(codes.Internal, "error configuring plugin %v.", plugin.PluginName)
		}

		result := methodCall.Call([]reflect.Value{reflect.ValueOf(ctx), reflect.ValueOf(req)})
		err := result[1]

		if !err.IsNil() {
			return nil, status.Errorf(codes.Internal, "error configuring one of the supplied plugins. The error was %v", err)
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

func (p *HybridPluginAgent) parseReceivedData(data common.Generics) (pluginNames []string, pluginsData map[string]string) {
	pluginNames = []string{}
	pluginsData = map[string]string{}
	var data_ bytes.Buffer
	for key := range data {
		data_.Reset()
		printer.DefaultConfig.Fprint(&data_, data[key])
		pluginInformedConfig := strings.Replace(strings.Replace(data_.String(), "{", "", -1), "}", "", -1)
		pluginsData[key] = pluginInformedConfig
		pluginNames = append(pluginNames, key)
	}

	return
}

func (p *HybridPluginAgent) initPlugins(pluginList []string) ([]common.Types, error) {
	attestors := make([]common.Types, len(pluginList))

	if len(attestors) == 0 {
		return nil, status.Error(codes.FailedPrecondition, "no plugins supplied")
	}

	for index, item := range pluginList {
		var plugin common.Types
		switch item {
		case "aws_iid":
			plugin.PluginName = "aws_iid"
			awsiid := awsiid.New()
			plugin.Plugin = awsiid
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
			return nil, status.Error(codes.FailedPrecondition, "please provide one of the supported plugins.")
		}

		elem := reflect.ValueOf(plugin.Plugin)
		methodCall := elem.MethodByName("SetLogger")

		if methodCall.Kind() != 0 {
			methodCall.Call([]reflect.Value{reflect.ValueOf(p.logger)})
		}

		attestors[index] = plugin
	}

	return attestors, nil
}
