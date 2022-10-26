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
