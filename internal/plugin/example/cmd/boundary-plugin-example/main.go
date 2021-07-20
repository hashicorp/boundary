package main

import (
	boundaryPlugin "github.com/hashicorp/boundary/internal/plugin"
	"github.com/hashicorp/boundary/internal/plugin/example"
	goPlugin "github.com/hashicorp/go-plugin"
)

// examplePlugin describes an instance of this example plugin.
type examplePlugin struct {
	// The sequence number.
	seq int32
}

// Hello implements the example Plugin interface.
func (p *examplePlugin) Hello() (int32, error) {
	p.seq++
	return p.seq, nil
}

func main() {
	goPlugin.Serve(&goPlugin.ServeConfig{
		HandshakeConfig: goPlugin.HandshakeConfig{
			ProtocolVersion:  1,
			MagicCookieKey:   boundaryPlugin.MagicCookieKey,
			MagicCookieValue: boundaryPlugin.MagicCookieValue,
		},
		Plugins: map[string]goPlugin.Plugin{
			"example": &example.ExampleGRPCPlugin{Impl: &examplePlugin{}},
		},

		// A non-nil value here enables gRPC serving for this plugin.
		GRPCServer: goPlugin.DefaultGRPCServer,
	})
}
