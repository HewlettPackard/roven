// package main

// import (
// 	"github.com/spiffe/spire-plugin-sdk/pluginmain"
// 	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
// 	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
// )

// func main() {
// 	p := hybrid_server.New()
// 	pluginmain.Serve(
// 		nodeattestorv1.NodeAttestorPluginServer(p),
// 		configv1.ConfigServiceServer(p),
// 	)
// }