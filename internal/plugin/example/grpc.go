package example

import (
	"context"

	"github.com/hashicorp/boundary/internal/plugin/example/proto"
)

// GRPCClient is an implementation of the Example interface that talks over
// RPC.
type GRPCClient struct{ client proto.ExampleClient }

func (m *GRPCClient) Hello() (int32, error) {
	resp, err := m.client.Hello(context.Background(), &proto.Empty{})
	if err != nil {
		return 0, err
	}

	return resp.GetSeq(), nil
}

// Here is the gRPC server that GRPCClient talks to.
type GRPCServer struct {
	proto.UnimplementedExampleServer

	// This is the real implementation
	Impl Example
}

func (m *GRPCServer) Hello(ctx context.Context, _ *proto.Empty) (*proto.HelloResponse, error) {
	seq, err := m.Impl.Hello()
	return &proto.HelloResponse{Seq: seq}, err
}
