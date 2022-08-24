package plugin

import (
	"context"

	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"google.golang.org/grpc"
)

var _ plgpb.HostPluginServiceClient = (*WrappingPluginClient)(nil)

// WrappingPluginClient provides a wrapper around a Server implementation that
// can be used when loading a plugin in-memory
type WrappingPluginClient struct {
	Server plgpb.HostPluginServiceServer
}

func NewWrappingPluginClient(s plgpb.HostPluginServiceServer) *WrappingPluginClient {
	return &WrappingPluginClient{Server: s}
}

func (tpc *WrappingPluginClient) NormalizeCatalogData(ctx context.Context, req *plgpb.NormalizeCatalogDataRequest, opts ...grpc.CallOption) (*plgpb.NormalizeCatalogDataResponse, error) {
	return tpc.Server.NormalizeCatalogData(ctx, req)
}

func (tpc *WrappingPluginClient) OnCreateCatalog(ctx context.Context, req *plgpb.OnCreateCatalogRequest, opts ...grpc.CallOption) (*plgpb.OnCreateCatalogResponse, error) {
	return tpc.Server.OnCreateCatalog(ctx, req)
}

func (tpc *WrappingPluginClient) OnUpdateCatalog(ctx context.Context, req *plgpb.OnUpdateCatalogRequest, opts ...grpc.CallOption) (*plgpb.OnUpdateCatalogResponse, error) {
	return tpc.Server.OnUpdateCatalog(ctx, req)
}

func (tpc *WrappingPluginClient) OnDeleteCatalog(ctx context.Context, req *plgpb.OnDeleteCatalogRequest, opts ...grpc.CallOption) (*plgpb.OnDeleteCatalogResponse, error) {
	return tpc.Server.OnDeleteCatalog(ctx, req)
}

func (tpc *WrappingPluginClient) NormalizeSetData(ctx context.Context, req *plgpb.NormalizeSetDataRequest, opts ...grpc.CallOption) (*plgpb.NormalizeSetDataResponse, error) {
	return tpc.Server.NormalizeSetData(ctx, req)
}

func (tpc *WrappingPluginClient) OnCreateSet(ctx context.Context, req *plgpb.OnCreateSetRequest, opts ...grpc.CallOption) (*plgpb.OnCreateSetResponse, error) {
	return tpc.Server.OnCreateSet(ctx, req)
}

func (tpc *WrappingPluginClient) OnUpdateSet(ctx context.Context, req *plgpb.OnUpdateSetRequest, opts ...grpc.CallOption) (*plgpb.OnUpdateSetResponse, error) {
	return tpc.Server.OnUpdateSet(ctx, req)
}

func (tpc *WrappingPluginClient) OnDeleteSet(ctx context.Context, req *plgpb.OnDeleteSetRequest, opts ...grpc.CallOption) (*plgpb.OnDeleteSetResponse, error) {
	return tpc.Server.OnDeleteSet(ctx, req)
}

func (tpc *WrappingPluginClient) ListHosts(ctx context.Context, req *plgpb.ListHostsRequest, opts ...grpc.CallOption) (*plgpb.ListHostsResponse, error) {
	return tpc.Server.ListHosts(ctx, req)
}
