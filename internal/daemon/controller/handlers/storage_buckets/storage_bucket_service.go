// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package storage_buckets

import (
	"context"

	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/globals"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	// IdActions contains the set of actions that can be performed on
	// individual resources
	IdActions = action.NewActionSet(
		action.NoOp,
		action.Read,
		action.Update,
		action.Delete,
	)

	// CollectionActions contains the set of actions that can be performed on
	// this collection
	CollectionActions = action.NewActionSet(
		action.Create,
		action.List,
	)
)

func init() {
	// TODO: refactor to remove IdActions and CollectionActions package variables
	action.RegisterResource(resource.StorageBucket, IdActions, CollectionActions)
}

// NewServiceFn returns a storage bucket service which is not implemented in OSS
var NewServiceFn = func(ctx context.Context,
	pluginStorageRepoFn common.PluginStorageBucketRepoFactory,
	iamRepoFn common.IamRepoFactory,
	pluginRepoFn common.PluginRepoFactory,
	maxPageSize uint,
	controllerExt globals.ControllerExtension,
) (pbs.StorageBucketServiceServer, error) {
	return Service{}, nil
}

type Service struct {
	pbs.UnimplementedStorageBucketServiceServer
}

var _ pbs.StorageBucketServiceServer = (*Service)(nil)

// ListStorageBuckets implements the interface pbs.StorageBucketServiceServer.
func (s Service) ListStorageBuckets(ctx context.Context, req *pbs.ListStorageBucketsRequest) (*pbs.ListStorageBucketsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "storage buckets are an Enterprise-only feature")
}

// GetStorageBucket implements the interface pbs.StorageBucketServiceServer.
func (s Service) GetStorageBucket(ctx context.Context, req *pbs.GetStorageBucketRequest) (*pbs.GetStorageBucketResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "storage buckets are an Enterprise-only feature")
}

// CreateStorageBucket implements the interface pbs.StorageBucketServiceServer.
func (s Service) CreateStorageBucket(ctx context.Context, req *pbs.CreateStorageBucketRequest) (*pbs.CreateStorageBucketResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "storage buckets are an Enterprise-only feature")
}

// UpdateStorageBucket implements the interface pbs.StorageBucketServiceServer.
func (s Service) UpdateStorageBucket(ctx context.Context, req *pbs.UpdateStorageBucketRequest) (*pbs.UpdateStorageBucketResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "storage buckets are an Enterprise-only feature")
}

// DeleteStorageBucket implements the interface pbs.StorageBucketServiceServer.
func (s Service) DeleteStorageBucket(ctx context.Context, req *pbs.DeleteStorageBucketRequest) (*pbs.DeleteStorageBucketResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "storage buckets are an Enterprise-only feature")
}
