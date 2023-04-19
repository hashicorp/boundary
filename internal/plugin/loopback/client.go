// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package loopback

import (
	"context"
	"errors"

	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"google.golang.org/grpc"
)

var _ plgpb.HostPluginServiceClient = (*WrappingPluginClient)(nil)

// WrappingPluginClient provides a wrapper around a Server implementation that
// can be used when loading a plugin in-memory. Supports HostServiceServer
type WrappingPluginClient struct {
	Server any
}

func NewWrappingPluginClient(s any) *WrappingPluginClient {
	return &WrappingPluginClient{Server: s}
}

func (tpc *WrappingPluginClient) NormalizeCatalogData(ctx context.Context, req *plgpb.NormalizeCatalogDataRequest, opts ...grpc.CallOption) (*plgpb.NormalizeCatalogDataResponse, error) {
	svc, ok := tpc.Server.(plgpb.HostPluginServiceServer)
	if !ok {
		return nil, errors.New("wrapping client not initialized with a HostServiceServer")
	}
	return svc.NormalizeCatalogData(ctx, req)
}

func (tpc *WrappingPluginClient) OnCreateCatalog(ctx context.Context, req *plgpb.OnCreateCatalogRequest, opts ...grpc.CallOption) (*plgpb.OnCreateCatalogResponse, error) {
	svc, ok := tpc.Server.(plgpb.HostPluginServiceServer)
	if !ok {
		return nil, errors.New("wrapping client not initialized with a HostServiceServer")
	}
	return svc.OnCreateCatalog(ctx, req)
}

func (tpc *WrappingPluginClient) OnUpdateCatalog(ctx context.Context, req *plgpb.OnUpdateCatalogRequest, opts ...grpc.CallOption) (*plgpb.OnUpdateCatalogResponse, error) {
	svc, ok := tpc.Server.(plgpb.HostPluginServiceServer)
	if !ok {
		return nil, errors.New("wrapping client not initialized with a HostServiceServer")
	}
	return svc.OnUpdateCatalog(ctx, req)
}

func (tpc *WrappingPluginClient) OnDeleteCatalog(ctx context.Context, req *plgpb.OnDeleteCatalogRequest, opts ...grpc.CallOption) (*plgpb.OnDeleteCatalogResponse, error) {
	svc, ok := tpc.Server.(plgpb.HostPluginServiceServer)
	if !ok {
		return nil, errors.New("wrapping client not initialized with a HostServiceServer")
	}
	return svc.OnDeleteCatalog(ctx, req)
}

func (tpc *WrappingPluginClient) NormalizeSetData(ctx context.Context, req *plgpb.NormalizeSetDataRequest, opts ...grpc.CallOption) (*plgpb.NormalizeSetDataResponse, error) {
	svc, ok := tpc.Server.(plgpb.HostPluginServiceServer)
	if !ok {
		return nil, errors.New("wrapping client not initialized with a HostServiceServer")
	}
	return svc.NormalizeSetData(ctx, req)
}

func (tpc *WrappingPluginClient) OnCreateSet(ctx context.Context, req *plgpb.OnCreateSetRequest, opts ...grpc.CallOption) (*plgpb.OnCreateSetResponse, error) {
	svc, ok := tpc.Server.(plgpb.HostPluginServiceServer)
	if !ok {
		return nil, errors.New("wrapping client not initialized with a HostServiceServer")
	}
	return svc.OnCreateSet(ctx, req)
}

func (tpc *WrappingPluginClient) OnUpdateSet(ctx context.Context, req *plgpb.OnUpdateSetRequest, opts ...grpc.CallOption) (*plgpb.OnUpdateSetResponse, error) {
	svc, ok := tpc.Server.(plgpb.HostPluginServiceServer)
	if !ok {
		return nil, errors.New("wrapping client not initialized with a HostServiceServer")
	}
	return svc.OnUpdateSet(ctx, req)
}

func (tpc *WrappingPluginClient) OnDeleteSet(ctx context.Context, req *plgpb.OnDeleteSetRequest, opts ...grpc.CallOption) (*plgpb.OnDeleteSetResponse, error) {
	svc, ok := tpc.Server.(plgpb.HostPluginServiceServer)
	if !ok {
		return nil, errors.New("wrapping client not initialized with a HostServiceServer")
	}
	return svc.OnDeleteSet(ctx, req)
}

func (tpc *WrappingPluginClient) ListHosts(ctx context.Context, req *plgpb.ListHostsRequest, opts ...grpc.CallOption) (*plgpb.ListHostsResponse, error) {
	svc, ok := tpc.Server.(plgpb.HostPluginServiceServer)
	if !ok {
		return nil, errors.New("wrapping client not initialized with a HostServiceServer")
	}
	return svc.ListHosts(ctx, req)
}
