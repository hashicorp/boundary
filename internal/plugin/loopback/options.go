// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package loopback

import (
	"strings"

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

	// Will return an error for the ListObjects method
	ListObjects
)

const (
	defaultStreamChunkSize = 8
)

// PluginMockError is used to mock an error when interacting with an external object store.
type PluginMockError struct {
	// BucketName is the name of the bucket to match on.
	BucketName string

	// BucketPrefix is the prefix of the bucket to match on.
	BucketPrefix string

	// ObjectKey is the object key to match on. This is optional and may be empty.
	// If empty, the error will match any object key, as long as the ErrPath is not set.
	// This is because the ErrPath is a less specific match than the ObjectKey.
	// The ObjectKey is ignored when the ErrPath is set.
	// The ObjectKey is also ignored for the following plugin methods: onCreateStorageBucket,
	// onUpdateStorageBucket, onDeleteStorageBucket as these methods do not provide an object key.
	ObjectKey string

	// ErrPath is the object key path prefix to match on. This is optional and may be empty.
	// If empty, the error will match any object key, as long as the ObjectKey is not set.
	// The ErrPath is ignored when the ObjectKey is set.
	// The ErrPath is also ignored for the following plugin methods: onCreateStorageBucket,
	// onUpdateStorageBucket, onDeleteStorageBucket as these methods do not provide an object key.
	// The ErrPath is used to match on a prefix of the object key. For example, if the ErrPath
	// is set to "path/to/obj", it will match any object key that starts with "path/to/obj",
	// such as "path/to/obj1", "path/to/obj2/subobj", etc.
	// This allows for more flexible error mocking based on object key prefixes.
	// The ErrPath should always end with a "/" if it is intended to match a directory prefix.
	// For example, to match all objects under "path/to/dir/", the ErrPath should be set to "path/to/dir/".
	// This ensures that it does not unintentionally match objects like "path/to/dir_obj".
	ErrPath string

	// ErrMsg is the error message to return.
	ErrMsg string

	// ErrCode is the gRPC error code to return.
	ErrCode codes.Code

	// ErrMethod is the plugin method to match on. This is optional and may be set to Any.
	// If set to Any, the error will be returned for any plugin method that matches the bucket
	// and object key criteria. If set to a specific method, the error will only be returned
	// for that method if the bucket and object key criteria also match.
	ErrMethod Method

	// StorageBucketCredentialState is the credential state to return.
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
	// if the mocked error object key is empty, it should match any key, as long as the ErrPath is not set.
	if key != "" && e.ObjectKey != "" && e.ObjectKey != key {
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
	// if the mocked error path is not empty and the key does not have the mocked error path as a prefix, return false.
	if e.ErrPath != "" && !strings.HasPrefix(key, e.ErrPath) {
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
