// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package loopback

import (
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/storagebuckets"
	"google.golang.org/grpc/codes"
)

// PluginMockError is used to mock an error when interacting with an external object store.
type PluginMockError struct {
	bucketName   string
	bucketPrefix string
	objectKey    string
	errMsg       string
	errCode      codes.Code
}

func (e PluginMockError) match(bucket *storagebuckets.StorageBucket, key string) bool {
	if key != "" && e.objectKey != key {
		return false
	}
	if e.bucketName != bucket.BucketName {
		return false
	}
	if bucket.BucketPrefix != "" && e.bucketPrefix != bucket.BucketPrefix {
		return false
	}
	return true
}

type TestOption func(*TestOptions) error

type TestOptions struct {
	withMockBuckets map[BucketName]Bucket
	withMockError   []PluginMockError
	withChunkSize   int
}

// getTestOpts - iterate the inbound Options and return a struct
func getTestOpts(opt ...TestOption) (TestOptions, error) {
	opts := getDefaultTestOptions()
	for _, o := range opt {
		if err := o(&opts); err != nil {
			return opts, err
		}
	}
	return opts, nil
}

func getDefaultTestOptions() TestOptions {
	return TestOptions{
		withChunkSize: 8,
	}
}

// WithMockBuckets provides an option to create mocked external object store buckets.
func WithMockBuckets(buckets map[BucketName]Bucket) TestOption {
	return func(o *TestOptions) error {
		o.withMockBuckets = buckets
		return nil
	}
}

// WithMockError provides an option to mock an error when interacting with an external object store.
func WithMockError(err PluginMockError) TestOption {
	return func(o *TestOptions) error {
		o.withMockError = append(o.withMockError, err)
		return nil
	}
}

// WithChunkSize provides an option to set the chunkSize used for grpc streams.
func WithChunkSize(size int) TestOption {
	return func(o *TestOptions) error {
		o.withChunkSize = size
		return nil
	}
}
