package example

import (
	"context"

	"github.com/hashicorp/boundary/internal/plugin/example/proto"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
)

// Example is an interface for an example plugin.
type Example interface {
	// Hello is a simple function that prints a sequence number locally
	// cached by the plugin.
	Hello() (int32, error)
}

// ExampleGRPCPlugin is an GRPC implementation of the Example plugin.
type ExampleGRPCPlugin struct {
	plugin.Plugin

	// Impl stores the implementation of this plugin.
	Impl Example
}

func (p *ExampleGRPCPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	proto.RegisterExampleServer(s, &GRPCServer{Impl: p.Impl})
	return nil
}

func (p *ExampleGRPCPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	// return &GRPCClient{client: proto.NewKVClient(c)}, nil
	return nil, nil
}
