// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package loopback

import (
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
)

const loopbackPluginHostInfoAttrField = "host_info"

var (
	_ plgpb.HostPluginServiceServer    = (*LoopbackPlugin)(nil)
	_ plgpb.StoragePluginServiceServer = (*LoopbackPlugin)(nil)
	_ plgpb.HostPluginServiceServer    = (*TestPluginServer)(nil)
	_ plgpb.StoragePluginServiceServer = (*TestPluginServer)(nil)
)

// TestPluginServer provides a host and storage plugin service server where each method can be overwritten for tests.
type TestPluginServer struct {
	TestPluginHostServer
	TestPluginStorageServer
}

// LoopbackPlugin provides a host and storage plugin with functionality useful for certain
// kinds of testing.
//
// It is not (currently) thread-safe.
//
// Over time, if useful, it can be enhanced to do things like handle multiple
// hosts per set.
type LoopbackPlugin struct {
	*TestPluginServer

	*LoopbackHost
	*LoopbackStorage
}

// NewLoopbackPlugin returns a new loopback plugin.
// For storage service testings NewLoopbackPlugin Supports WithMockErrors
// and WithMockBuckets as options. If no mock buckets are provided,
// a bucket named `default` will be created.
func NewLoopbackPlugin(opt ...TestOption) (*LoopbackPlugin, error) {
	opts, err := getTestOpts(opt...)
	if err != nil {
		return nil, err
	}

	ret := &LoopbackPlugin{
		TestPluginServer: new(TestPluginServer),
		LoopbackHost: &LoopbackHost{
			hostMap: make(map[string][]*loopbackPluginHostInfo),
		},
		LoopbackStorage: &LoopbackStorage{
			chunksSize:        opts.withChunkSize,
			buckets:           map[BucketName]Bucket{"default": {}},
			errs:              make([]PluginMockError, 0),
			putObjectResponse: make([]PluginMockPutObjectResponse, 0),
		},
	}

	// Set host methods
	ret.OnCreateCatalogFn = ret.onCreateCatalog
	ret.OnUpdateCatalogFn = ret.onUpdateCatalog
	ret.OnCreateSetFn = ret.onCreateSet
	ret.OnUpdateSetFn = ret.onUpdateSet
	ret.OnDeleteSetFn = ret.onDeleteSet
	ret.ListHostsFn = ret.listHosts

	// Set storage methods
	ret.OnCreateStorageBucketFn = ret.onCreateStorageBucket
	ret.OnUpdateStorageBucketFn = ret.onUpdateStorageBucket
	ret.OnDeleteStorageBucketFn = ret.onDeleteStorageBucket
	ret.ValidatePermissionsFn = ret.validatePermissions
	ret.HeadObjectFn = ret.headObject
	ret.GetObjectFn = ret.getObject
	ret.PutObjectFn = ret.putObject
	ret.DeleteObjectsFn = ret.deleteObjects
	if len(opts.withMockBuckets) > 0 {
		ret.buckets = opts.withMockBuckets
	}
	if len(opts.withMockError) > 0 {
		ret.errs = opts.withMockError
	}
	if len(opts.withMockPutObjectResponse) > 0 {
		ret.putObjectResponse = opts.withMockPutObjectResponse
	}

	return ret, nil
}
