// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package loopback

import (
	"context"

	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"google.golang.org/grpc"
)

var (
	_ plgpb.HostPluginServiceClient    = (*WrappingPluginHostClient)(nil)
	_ plgpb.StoragePluginServiceClient = (*WrappingPluginStorageClient)(nil)
)

// WrappingPluginHostClient provides a wrapper around a Server implementation that
// can be used when loading a plugin in-memory. Supports HostServiceServer
type WrappingPluginHostClient struct {
	Server plgpb.HostPluginServiceServer
}

func NewWrappingPluginHostClient(s plgpb.HostPluginServiceServer) *WrappingPluginHostClient {
	return &WrappingPluginHostClient{Server: s}
}

func (tpc *WrappingPluginHostClient) NormalizeCatalogData(ctx context.Context, req *plgpb.NormalizeCatalogDataRequest, opts ...grpc.CallOption) (*plgpb.NormalizeCatalogDataResponse, error) {
	return tpc.Server.NormalizeCatalogData(ctx, req)
}

func (tpc *WrappingPluginHostClient) OnCreateCatalog(ctx context.Context, req *plgpb.OnCreateCatalogRequest, opts ...grpc.CallOption) (*plgpb.OnCreateCatalogResponse, error) {
	return tpc.Server.OnCreateCatalog(ctx, req)
}

func (tpc *WrappingPluginHostClient) OnUpdateCatalog(ctx context.Context, req *plgpb.OnUpdateCatalogRequest, opts ...grpc.CallOption) (*plgpb.OnUpdateCatalogResponse, error) {
	return tpc.Server.OnUpdateCatalog(ctx, req)
}

func (tpc *WrappingPluginHostClient) OnDeleteCatalog(ctx context.Context, req *plgpb.OnDeleteCatalogRequest, opts ...grpc.CallOption) (*plgpb.OnDeleteCatalogResponse, error) {
	return tpc.Server.OnDeleteCatalog(ctx, req)
}

func (tpc *WrappingPluginHostClient) NormalizeSetData(ctx context.Context, req *plgpb.NormalizeSetDataRequest, opts ...grpc.CallOption) (*plgpb.NormalizeSetDataResponse, error) {
	return tpc.Server.NormalizeSetData(ctx, req)
}

func (tpc *WrappingPluginHostClient) OnCreateSet(ctx context.Context, req *plgpb.OnCreateSetRequest, opts ...grpc.CallOption) (*plgpb.OnCreateSetResponse, error) {
	return tpc.Server.OnCreateSet(ctx, req)
}

func (tpc *WrappingPluginHostClient) OnUpdateSet(ctx context.Context, req *plgpb.OnUpdateSetRequest, opts ...grpc.CallOption) (*plgpb.OnUpdateSetResponse, error) {
	return tpc.Server.OnUpdateSet(ctx, req)
}

func (tpc *WrappingPluginHostClient) OnDeleteSet(ctx context.Context, req *plgpb.OnDeleteSetRequest, opts ...grpc.CallOption) (*plgpb.OnDeleteSetResponse, error) {
	return tpc.Server.OnDeleteSet(ctx, req)
}

func (tpc *WrappingPluginHostClient) ListHosts(ctx context.Context, req *plgpb.ListHostsRequest, opts ...grpc.CallOption) (*plgpb.ListHostsResponse, error) {
	return tpc.Server.ListHosts(ctx, req)
}

// WrappingPluginStorageClient provides a wrapper around a Server implementation that
// can be used when loading a plugin in-memory. Supports StoragePluginServiceClient
type WrappingPluginStorageClient struct {
	Server plgpb.StoragePluginServiceServer
}

func NewWrappingPluginStorageClient(s plgpb.StoragePluginServiceServer) *WrappingPluginStorageClient {
	return &WrappingPluginStorageClient{Server: s}
}

func (tpc *WrappingPluginStorageClient) NormalizeStorageBucketData(ctx context.Context, req *plgpb.NormalizeStorageBucketDataRequest, opts ...grpc.CallOption) (*plgpb.NormalizeStorageBucketDataResponse, error) {
	return tpc.Server.NormalizeStorageBucketData(ctx, req)
}

func (tpc *WrappingPluginStorageClient) OnCreateStorageBucket(ctx context.Context, req *plgpb.OnCreateStorageBucketRequest, opts ...grpc.CallOption) (*plgpb.OnCreateStorageBucketResponse, error) {
	return tpc.Server.OnCreateStorageBucket(ctx, req)
}

func (tpc *WrappingPluginStorageClient) OnUpdateStorageBucket(ctx context.Context, req *plgpb.OnUpdateStorageBucketRequest, opts ...grpc.CallOption) (*plgpb.OnUpdateStorageBucketResponse, error) {
	return tpc.Server.OnUpdateStorageBucket(ctx, req)
}

func (tpc *WrappingPluginStorageClient) OnDeleteStorageBucket(ctx context.Context, req *plgpb.OnDeleteStorageBucketRequest, opts ...grpc.CallOption) (*plgpb.OnDeleteStorageBucketResponse, error) {
	return tpc.Server.OnDeleteStorageBucket(ctx, req)
}

func (tpc *WrappingPluginStorageClient) HeadObject(ctx context.Context, req *plgpb.HeadObjectRequest, opts ...grpc.CallOption) (*plgpb.HeadObjectResponse, error) {
	return tpc.Server.HeadObject(ctx, req)
}

func (tpc *WrappingPluginStorageClient) ValidatePermissions(ctx context.Context, req *plgpb.ValidatePermissionsRequest, opts ...grpc.CallOption) (*plgpb.ValidatePermissionsResponse, error) {
	return tpc.Server.ValidatePermissions(ctx, req)
}

func (tpc *WrappingPluginStorageClient) GetObject(ctx context.Context, req *plgpb.GetObjectRequest, opts ...grpc.CallOption) (plgpb.StoragePluginService_GetObjectClient, error) {
	stream := newGetObjectStream()
	if err := tpc.Server.GetObject(req, stream.server); err != nil {
		return nil, err
	}
	return stream.client, nil
}

func (tpc *WrappingPluginStorageClient) PutObject(ctx context.Context, req *plgpb.PutObjectRequest, opts ...grpc.CallOption) (*plgpb.PutObjectResponse, error) {
	return tpc.Server.PutObject(ctx, req)
}

func (tpc *WrappingPluginStorageClient) DeleteObjects(ctx context.Context, req *plgpb.DeleteObjectsRequest, opts ...grpc.CallOption) (*plgpb.DeleteObjectsResponse, error) {
	return tpc.Server.DeleteObjects(ctx, req)
}
