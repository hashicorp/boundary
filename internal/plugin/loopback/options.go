// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package loopback

import (
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/storagebuckets"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"google.golang.org/grpc/codes"
)

// Method is used to determine if an error should be returned to a specific storage plugin method.
type Method uint8

const (
	// Any will return an error for any of the method defined in the storage plugin.
	Any Method = iota

	// Will return an error for the OnCreateStorageBucket method
	OnCreateStorageBucket

	// Will return an error for the OnUpdateStorageBucket method
	OnUpdateStorageBucket

	// Will return an error for the OnDeleteStorageBucket method
	OnDeleteStorageBucket

	// Will return an error for the ValidatePermissions method
	ValidatePermissions

	// Will return an error for the HeadObject method
	HeadObject

	// Will return an error for the GetObject method
	GetObject

	// Will return an error for the PutObject method
	PutObject

	// Will return an error for the DeleteObjects method
	DeleteObjects
)

const (
	defaultStreamChunkSize = 8
)

// PluginMockError is used to mock an error when interacting with an external object store.
type PluginMockError struct {
	BucketName                   string
	BucketPrefix                 string
	ObjectKey                    string
	ErrMsg                       string
	ErrCode                      codes.Code
	ErrMethod                    Method
	StorageBucketCredentialState *plgpb.StorageBucketCredentialState
}

// match compares the given values from the parameters to the values provided in the mocked error.
// The bucket and key parameter values should be provided from the plugin request. The method
// value should be based on the plugin method that is calling this function.
//
// When match returns false, the mocked error should not be used for the plugin response.
// When match returns true, the mocked error should be used for the plugin response.
func (e PluginMockError) match(bucket *storagebuckets.StorageBucket, key string, method Method) bool {
	// if the mocked error object key does not match the request's object key, return false.
	// the object key comparison is ignored when the given key is empty because the following
	// plugin methods do not provide key values: onCreateStorageBucket, onUpdateStorageBucket,
	// onDeleteStorageBucket
	if key != "" && e.ObjectKey != key {
		return false
	}
	// if the mocked error bucket name does not match the request's bucket name, return false.
	if e.BucketName != bucket.BucketName {
		return false
	}
	// if the request has a bucket prefix and it does not match the mocked error bucket prefix, return false.
	if bucket.BucketPrefix != "" && e.BucketPrefix != bucket.BucketPrefix {
		return false
	}
	// if the mocked error method is set to Any, return true. This means that the mocked error response
	// will be utilized by all the plugin methods.
	if e.ErrMethod == Any {
		return true
	}
	// if the mocked error method does match the given method, return false.
	if e.ErrMethod != method {
		return false
	}
	// all checks comparison checks passed, return true.
	return true
}

// PluginMockPutObjectResponse is used to mock a response when calling putObject.
type PluginMockPutObjectResponse struct {
	BucketName   string
	BucketPrefix string
	ObjectKey    string
	Response     *plgpb.PutObjectResponse
}

// match compares the given values from the parameters to the values provided in the mocked response.
// The bucket and key parameter values should be provided from the plugin request.
//
// When match returns false, the mocked response should not be used for the plugin response.
// When match returns true, the mocked response should be used for the plugin response.
func (r PluginMockPutObjectResponse) match(bucket *storagebuckets.StorageBucket, key string) bool {
	// if the mocked response object key does not match the request's object key, return false.
	if r.ObjectKey != key {
		return false
	}
	// if the mocked response bucket name does not match the request's bucket name, return false.
	if r.BucketName != bucket.BucketName {
		return false
	}
	// if the request has a bucket prefix and it does not match the mocked response bucket prefix, return false.
	if bucket.BucketPrefix != "" && r.BucketPrefix != bucket.BucketPrefix {
		return false
	}
	// all checks comparison checks passed, return true.
	return true
}

type TestOption func(*TestOptions) error

type TestOptions struct {
	withMockBuckets           map[BucketName]Bucket
	withMockError             []PluginMockError
	withMockPutObjectResponse []PluginMockPutObjectResponse
	withChunkSize             int
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

func WithMockPutObjectResponse(response PluginMockPutObjectResponse) TestOption {
	return func(o *TestOptions) error {
		o.withMockPutObjectResponse = append(o.withMockPutObjectResponse, response)
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
