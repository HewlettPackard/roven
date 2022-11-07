package common

import (
	"github.com/hashicorp/hcl/hcl/ast"
)

type Types struct {
	PluginName string
	Plugin     interface{}
}

type Generics map[string]ast.Node

type GenericPluginSuper struct {
	Plugins ast.Node `hcl:"plugins"`
}

type PluginMessage struct {
	PluginName string `json:"plugin_name"`
	PluginData []byte `json:"plugin_data"`
}

type PluginMessageList struct {
	Messages []PluginMessage `json:"messages"`
}
