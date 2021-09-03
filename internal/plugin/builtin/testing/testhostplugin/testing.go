package testhostplugin

import (
	"context"

	"github.com/hashicorp/boundary/plugin/proto"
	"google.golang.org/grpc"
)

// TestHostPlugin is an internal plugin used for testing the host
// plugin system.
type TestHostPlugin struct{}

// NewClient returns a HostPluginServiceClient for TestHostPlugin.
func NewClient() proto.HostPluginServiceClient {
	return &TestHostPlugin{}
}

// OnCreateCatalog implements HostPluginServiceClient for TestHostPlugin.
func (p *TestHostPlugin) OnCreateCatalog(ctx context.Context, in *proto.OnCreateCatalogRequest, _ ...grpc.CallOption) (*proto.OnCreateCatalogResponse, error) {
	return &proto.OnCreateCatalogResponse{}, nil
}

// OnUpdateCatalog implements HostPluginServiceClient for TestHostPlugin.
func (p *TestHostPlugin) OnUpdateCatalog(ctx context.Context, in *proto.OnUpdateCatalogRequest, _ ...grpc.CallOption) (*proto.OnUpdateCatalogResponse, error) {
	return &proto.OnUpdateCatalogResponse{}, nil
}

// OnDeleteCatalog implements HostPluginServiceClient for TestHostPlugin.
func (p *TestHostPlugin) OnDeleteCatalog(ctx context.Context, in *proto.OnDeleteCatalogRequest, _ ...grpc.CallOption) (*proto.OnDeleteCatalogResponse, error) {
	return &proto.OnDeleteCatalogResponse{}, nil
}

// OnCreateSet implements HostPluginServiceClient for TestHostPlugin.
func (p *TestHostPlugin) OnCreateSet(ctx context.Context, in *proto.OnCreateSetRequest, _ ...grpc.CallOption) (*proto.OnCreateSetResponse, error) {
	return &proto.OnCreateSetResponse{}, nil
}

// OnUpdateSet implements HostPluginServiceClient for TestHostPlugin.
func (p *TestHostPlugin) OnUpdateSet(ctx context.Context, in *proto.OnUpdateSetRequest, _ ...grpc.CallOption) (*proto.OnUpdateSetResponse, error) {
	return &proto.OnUpdateSetResponse{}, nil
}

// OnDeleteSet implements HostPluginServiceClient for TestHostPlugin.
func (p *TestHostPlugin) OnDeleteSet(ctx context.Context, in *proto.OnDeleteSetRequest, opts ...grpc.CallOption) (*proto.OnDeleteSetResponse, error) {
	return &proto.OnDeleteSetResponse{}, nil
}

// ListHosts implements HostPluginServiceClient for TestHostPlugin.
func (p *TestHostPlugin) ListHosts(ctx context.Context, in *proto.ListHostsRequest, opts ...grpc.CallOption) (*proto.ListHostsResponse, error) {
	return &proto.ListHostsResponse{}, nil
}
