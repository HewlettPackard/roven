package hybridserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"

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
	nodeattestorbase.Base
	agentstorev1.UnimplementedAgentStoreServer
	nodeattestorv1.UnimplementedNodeAttestorServer
	configv1.UnsafeConfigServer

	pluginList []common.Types
	logger     hclog.Logger
	store      agentstorev1.AgentStoreServiceClient
	broker     pluginsdk.ServiceBroker
	mu         sync.RWMutex
}

func New() *HybridPluginServer {
	return &HybridPluginServer{}
}

func (p *HybridPluginServer) CheckAttested(ctx context.Context, spiffeID string) (bool, error) {
	return agentstore.IsAttested(ctx, p.store, spiffeID)
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
		return errors.New("agent store service required")
	}

	for _, plugin := range p.pluginList {
		elem := reflect.ValueOf(plugin.Plugin)
		method := elem.MethodByName("BrokerHostServices")
		if method.IsValid() {
			err := elem.MethodByName("BrokerHostServices").Call([]reflect.Value{reflect.ValueOf(p.broker)})

			if err[0].Interface() != nil {
				return status.Errorf(codes.Internal, "%v", err)
			}
		}
	}

	return nil
}

func (p *HybridPluginServer) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {
	req, err := stream.Recv()
	if err != nil {
		return err
	}

	payloadRequest, ok := req.Request.(*nodeattestorv1.AttestRequest_Payload)
	if !ok {
		return status.Errorf(codes.InvalidArgument, "request payload is required")
	}

	var messageList common.PluginMessageList
	if err := json.Unmarshal(payloadRequest.Payload, &messageList); err != nil {
		return status.Errorf(codes.InvalidArgument, "unable to unmarshal payload: %v", err)
	}

	payloadMap := map[string][]byte{}
	for _, message := range messageList.Messages {
		payloadMap[message.PluginName] = message.PluginData
	}

	interceptors := make([]ServerInterceptor, len(messageList.Messages))

	for index, plugin := range p.pluginList {
		if val, ok := payloadMap[plugin.PluginName]; ok {

			newReq := &nodeattestorv1.AttestRequest{
				Request: &nodeattestorv1.AttestRequest_Payload{
					Payload: val,
				},
			}

			newInterceptor := NewServerInterceptor()
			newInterceptor.SetReq(newReq)
			newInterceptor.setCustomStream(stream)
			interceptors[index] = newInterceptor

			elem := reflect.ValueOf(plugin.Plugin)
			result := elem.MethodByName("Attest").Call([]reflect.Value{reflect.ValueOf(newInterceptor)})

			if result[0].Interface() != nil {
				callError, _ := status.FromError(result[0].Interface().(error))
				return status.Errorf(codes.Internal, callError.Message())
			}
		} else {
			return status.Errorf(codes.InvalidArgument, "plugin %v not found", plugin.PluginName)
		}
	}

	return p.SendResponse(interceptors, stream)
}

func (p *HybridPluginServer) SendResponse(interceptors []ServerInterceptor, stream nodeattestorv1.NodeAttestor_AttestServer) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	selectors := []string{}
	canReattest := true
	spiffeId := interceptors[0].SpiffeID()

	for _, interceptor := range interceptors {
		if !p.checkReattestation(interceptor.CanReattest()) {
			attested, err := p.CheckAttested(interceptor.Context(), interceptor.SpiffeID())
			canReattest = false
			switch {
			case err != nil:
				return err
			case attested:
				return status.Error(codes.PermissionDenied, "attestation data has already been used to attest an agent")
			default:
			}
		}

		selectors = append(selectors, interceptor.CombinedSelectors()...)
	}

	return stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				CanReattest:    canReattest,
				SpiffeId:       spiffeId,
				SelectorValues: selectors,
			},
		},
	})
}

func (p *HybridPluginServer) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	pluginData, configError := p.decodeStringAndTransformToAstNode(req.HclConfiguration)

	if configError != nil {
		return nil, configError
	}

	pluginNames, pluginsData := p.parseReceivedData(pluginData)

	var initError error
	p.pluginList, initError = p.initPlugins(pluginNames)

	if len(p.pluginList) == 0 || initError != nil {
		return nil, initError
	}

	for _, plugin := range p.pluginList {
		elem := reflect.ValueOf(plugin.Plugin)
		req.HclConfiguration = pluginsData[plugin.PluginName]

		if len(req.HclConfiguration) == 0 {
			return nil, status.Errorf(codes.Internal, "error getting data from one of the supplied plugins: %s", plugin.PluginName)
		}

		result := elem.MethodByName("Configure").Call([]reflect.Value{reflect.ValueOf(ctx), reflect.ValueOf(req)})
		err := result[1]

		if !err.IsNil() {
			return nil, status.Errorf(codes.Internal, "error configuring one of the supplied plugins(%s): %s", plugin.PluginName, err.Interface().(error))
		}
	}

	if err := p.setBrokerHostServices(); err != nil {
		return nil, err
	}

	return &configv1.ConfigureResponse{}, nil
}

func (p *HybridPluginServer) decodeStringAndTransformToAstNode(hclData string) (common.Generics, error) {
	var genericData common.GenericPluginSuper
	if err := hcl.Decode(&genericData, hclData); err != nil {
		return nil, status.Errorf(codes.Internal, "could not decode HCL config. The error was %v.", err)
	}

	var data bytes.Buffer
	printer.DefaultConfig.Fprint(&data, genericData.Plugins)

	var astNodeData common.Generics

	if err := hcl.Decode(&astNodeData, data.String()); err != nil {
		return nil, status.Errorf(codes.Internal, "could not decode HCL config. The error was %v.", err)
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
		result = reverse(strings.Replace(reverse(result), "}", "", 1))
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
	if len(pluginList) == 0 {
		return nil, status.Error(codes.FailedPrecondition, "no plugins supplied")
	}

	attestors := make([]common.Types, len(pluginList))

	for index, item := range pluginList {
		var plugin common.Types
		switch item {
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

func (p *HybridPluginServer) checkReattestation(attestationData []bool) bool {
	for _, canReattest := range attestationData {
		if !canReattest {
			return false
		}
	}

	return true
}
