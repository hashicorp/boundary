// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package loopback

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"sync"
	"testing"

	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/storagebuckets"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	ta "github.com/stretchr/testify/assert"
	tr "github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestLoopbackOnCreateStorageBucket(t *testing.T) {
	require, assert := tr.New(t), ta.New(t)

	plg, err := NewLoopbackPlugin(
		WithMockBuckets(map[BucketName]Bucket{
			"aws_s3_mock": {},
			"aws_s3_err":  {},
		}),
		WithMockError(PluginMockError{
			bucketName: "aws_s3_err",
			errMsg:     "invalid credentials",
			errCode:    codes.PermissionDenied,
		}),
	)
	assert.NoError(err)

	client := NewWrappingPluginStorageClient(plg)
	secrets := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			"AWS_ACCESS_KEY_ID":     structpb.NewStringValue("access_key_id"),
			"AWS_SECRET_ACCESS_KEY": structpb.NewStringValue("secret_access_key"),
		},
	}

	tests := []struct {
		name        string
		request     *plgpb.OnCreateStorageBucketRequest
		expectedErr codes.Code
	}{
		{
			name:        "missing request",
			expectedErr: codes.InvalidArgument,
		},
		{
			name:        "missing storage bucket",
			request:     &plgpb.OnCreateStorageBucketRequest{},
			expectedErr: codes.InvalidArgument,
		},
		{
			name: "missing secrets",
			request: &plgpb.OnCreateStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_mock",
				},
			},
			expectedErr: codes.InvalidArgument,
		},
		{
			name: "unknown bucket",
			request: &plgpb.OnCreateStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "bucket_dne",
					Secrets:    secrets,
				},
			},
			expectedErr: codes.NotFound,
		},
		{
			name: "mocked error",
			request: &plgpb.OnCreateStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_err",
					Secrets:    secrets,
				},
			},
			expectedErr: codes.PermissionDenied,
		},
		{
			name: "valid credentials",
			request: &plgpb.OnCreateStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_mock",
					Secrets:    secrets,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := client.OnCreateStorageBucket(context.Background(), tt.request)
			if tt.expectedErr != codes.OK {
				assert.Error(err)
				assert.Nil(response)
				s, ok := status.FromError(err)
				require.True(ok, "invalid error type")
				assert.Equal(tt.expectedErr, s.Code())
				return
			}

			assert.NoError(err)
			require.NotNil(response)
			assert.NotNil(response.GetPersisted())
			assert.NotNil(response.GetPersisted().GetData())
			assert.EqualValues(tt.request.GetBucket().GetSecrets().AsMap(), response.GetPersisted().GetData().AsMap())
		})
	}
}

func TestLoopbackOnUpdateStorageBucket(t *testing.T) {
	require, assert := tr.New(t), ta.New(t)

	plg, err := NewLoopbackPlugin(
		WithMockBuckets(map[BucketName]Bucket{
			"aws_s3_mock": {},
			"aws_s3_err":  {},
		}),
		WithMockError(PluginMockError{
			bucketName: "aws_s3_err",
			errMsg:     "invalid credentials",
			errCode:    codes.PermissionDenied,
		}),
	)
	assert.NoError(err)

	client := NewWrappingPluginStorageClient(plg)
	secrets := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			"AWS_ACCESS_KEY_ID":     structpb.NewStringValue("access_key_id"),
			"AWS_SECRET_ACCESS_KEY": structpb.NewStringValue("secret_access_key"),
		},
	}

	tests := []struct {
		name        string
		request     *plgpb.OnUpdateStorageBucketRequest
		expectedErr codes.Code
	}{
		{
			name:        "missing request",
			expectedErr: codes.InvalidArgument,
		},
		{
			name:        "missing storage bucket",
			request:     &plgpb.OnUpdateStorageBucketRequest{},
			expectedErr: codes.InvalidArgument,
		},
		{
			name: "missing secrets",
			request: &plgpb.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_mock",
				},
			},
			expectedErr: codes.InvalidArgument,
		},
		{
			name: "unknown bucket",
			request: &plgpb.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "bucket_dne",
					Secrets:    secrets,
				},
			},
			expectedErr: codes.NotFound,
		},
		{
			name: "mocked error",
			request: &plgpb.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_err",
					Secrets:    secrets,
				},
			},
			expectedErr: codes.PermissionDenied,
		},
		{
			name: "valid credentials",
			request: &plgpb.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_mock",
					Secrets:    secrets,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := client.OnUpdateStorageBucket(context.Background(), tt.request)
			if tt.expectedErr != codes.OK {
				assert.Error(err)
				assert.Nil(response)
				s, ok := status.FromError(err)
				require.True(ok, "invalid error type")
				assert.Equal(tt.expectedErr, s.Code())
				return
			}

			assert.NoError(err)
			require.NotNil(response)
			assert.NotNil(response.GetPersisted())
			assert.NotNil(response.GetPersisted().GetData())
			assert.EqualValues(tt.request.GetNewBucket().GetSecrets().AsMap(), response.GetPersisted().GetData().AsMap())
		})
	}
}

func TestLoopbackOnDeleteStorageBucket(t *testing.T) {
	require, assert := tr.New(t), ta.New(t)

	plg, err := NewLoopbackPlugin()
	assert.NoError(err)

	client := NewWrappingPluginStorageClient(plg)
	secrets := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			"AWS_ACCESS_KEY_ID":     structpb.NewStringValue("access_key_id"),
			"AWS_SECRET_ACCESS_KEY": structpb.NewStringValue("secret_access_key"),
		},
	}

	tests := []struct {
		name        string
		request     *plgpb.OnDeleteStorageBucketRequest
		expectedErr codes.Code
	}{
		{
			name:        "missing request",
			expectedErr: codes.InvalidArgument,
		},
		{
			name:        "missing storage bucket",
			request:     &plgpb.OnDeleteStorageBucketRequest{},
			expectedErr: codes.InvalidArgument,
		},
		{
			name: "missing secrets",
			request: &plgpb.OnDeleteStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_mock",
				},
			},
			expectedErr: codes.InvalidArgument,
		},
		{
			name: "valid credentials",
			request: &plgpb.OnDeleteStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_mock",
					Secrets:    secrets,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := client.OnDeleteStorageBucket(context.Background(), tt.request)
			if tt.expectedErr != codes.OK {
				assert.Error(err)
				assert.Nil(response)
				s, ok := status.FromError(err)
				require.True(ok, "invalid error type")
				assert.Equal(s.Code(), tt.expectedErr)
				return
			}

			assert.NoError(err)
			require.NotNil(response)
		})
	}
}

func TestLoopbackValidatePermissions(t *testing.T) {
	require, assert := tr.New(t), ta.New(t)

	plg, err := NewLoopbackPlugin(
		WithMockBuckets(map[BucketName]Bucket{
			"aws_s3_mock": {},
			"aws_s3_err":  {},
		}),
		WithMockError(PluginMockError{
			bucketName: "aws_s3_err",
			errMsg:     "invalid credentials",
			errCode:    codes.PermissionDenied,
		}),
	)
	assert.NoError(err)

	client := NewWrappingPluginStorageClient(plg)
	secrets := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			"AWS_ACCESS_KEY_ID":     structpb.NewStringValue("access_key_id"),
			"AWS_SECRET_ACCESS_KEY": structpb.NewStringValue("secret_access_key"),
		},
	}

	tests := []struct {
		name        string
		request     *plgpb.ValidatePermissionsRequest
		expectedErr codes.Code
	}{
		{
			name:        "missing request",
			expectedErr: codes.InvalidArgument,
		},
		{
			name:        "missing storage bucket",
			request:     &plgpb.ValidatePermissionsRequest{},
			expectedErr: codes.InvalidArgument,
		},
		{
			name: "missing secrets",
			request: &plgpb.ValidatePermissionsRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_mock",
				},
			},
			expectedErr: codes.InvalidArgument,
		},
		{
			name: "unknown bucket",
			request: &plgpb.ValidatePermissionsRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "bucket_dne",
					Secrets:    secrets,
				},
			},
			expectedErr: codes.NotFound,
		},
		{
			name: "mocked error",
			request: &plgpb.ValidatePermissionsRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_err",
					Secrets:    secrets,
				},
			},
			expectedErr: codes.PermissionDenied,
		},
		{
			name: "valid credentials",
			request: &plgpb.ValidatePermissionsRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_mock",
					Secrets:    secrets,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := client.ValidatePermissions(context.Background(), tt.request)
			if tt.expectedErr != codes.OK {
				assert.Error(err)
				assert.Nil(response)
				s, ok := status.FromError(err)
				require.True(ok, "invalid error type")
				assert.Equal(tt.expectedErr, s.Code())
				return
			}

			assert.NoError(err)
			require.NotNil(response)
		})
	}
}

func TestLoopbackHeadObject(t *testing.T) {
	require, assert := tr.New(t), ta.New(t)

	mockStorageMapData := map[BucketName]Bucket{
		"aws_s3_mock": {
			"mock_object": MockObject([]Chunk{
				[]byte("THIS IS A MOCKED OBJECT"),
			}),
		},
		"aws_s3_err": {
			"mock_object": MockObject([]Chunk{
				[]byte("THIS IS A MOCKED OBJECT"),
			}),
		},
	}

	plg, err := NewLoopbackPlugin(
		WithMockBuckets(mockStorageMapData),
		WithMockError(PluginMockError{
			bucketName: "aws_s3_err",
			objectKey:  "mock_object",
			errMsg:     "invalid credentials",
			errCode:    codes.PermissionDenied,
		}),
	)
	assert.NoError(err)

	client := NewWrappingPluginStorageClient(plg)
	secrets := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			"AWS_ACCESS_KEY_ID":     structpb.NewStringValue("access_key_id"),
			"AWS_SECRET_ACCESS_KEY": structpb.NewStringValue("secret_access_key"),
		},
	}

	tests := []struct {
		name        string
		request     *plgpb.HeadObjectRequest
		expectedErr codes.Code
		expectedObj *storagePluginStorageInfo
	}{
		{
			name:        "missing request",
			expectedErr: codes.InvalidArgument,
		},
		{
			name:        "missing storage bucket",
			request:     &plgpb.HeadObjectRequest{},
			expectedErr: codes.InvalidArgument,
		},
		{
			name: "missing secrets",
			request: &plgpb.HeadObjectRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_mock",
				},
			},
			expectedErr: codes.InvalidArgument,
		},
		{
			name: "emtpy object key",
			request: &plgpb.HeadObjectRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_mock",
					Secrets:    secrets,
				},
			},
			expectedErr: codes.InvalidArgument,
		},
		{
			name: "bucket not found",
			request: &plgpb.HeadObjectRequest{
				Key: "mock_object",
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "invalid_bucket",
					Secrets:    secrets,
				},
			},
			expectedErr: codes.NotFound,
		},
		{
			name: "object not found",
			request: &plgpb.HeadObjectRequest{
				Key: "invalid_object_key",
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_mock",
					Secrets:    secrets,
				},
			},
			expectedErr: codes.NotFound,
		},
		{
			name: "mocked error",
			request: &plgpb.HeadObjectRequest{
				Key: "mock_object",
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_err",
					Secrets:    secrets,
				},
			},
			expectedErr: codes.PermissionDenied,
		},
		{
			name: "head retrieved",
			request: &plgpb.HeadObjectRequest{
				Key: "mock_object",
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_mock",
					Secrets:    secrets,
				},
			},
			expectedObj: mockStorageMapData["aws_s3_mock"]["mock_object"],
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := client.HeadObject(context.Background(), tt.request)
			if tt.expectedErr != codes.OK {
				assert.Error(err)
				assert.Nil(resp)
				s, ok := status.FromError(err)
				require.True(ok, "invalid error type")
				assert.Equal(s.Code(), tt.expectedErr)
				return
			}
			assert.NoError(err)
			assert.NotNil(resp)
			assert.NotNil(tt.expectedObj)
			assert.Equal(*tt.expectedObj.contentLength, resp.ContentLength)
			assert.Equal(tt.expectedObj.lastModified.UTC().String(), resp.LastModified.AsTime().String())
		})
	}
}

func TestLoopbackGetObject(t *testing.T) {
	require, assert := tr.New(t), ta.New(t)

	mockStorageMapData := map[BucketName]Bucket{
		"aws_s3_mock": {
			"mock_object": MockObject([]Chunk{
				[]byte("THIS IS A MOCKED OBJECT"),
			}),
		},
		"aws_s3_err": {
			"mock_object": MockObject([]Chunk{
				[]byte("THIS IS A MOCKED OBJECT"),
			}),
		},
	}

	plg, err := NewLoopbackPlugin(
		WithMockBuckets(mockStorageMapData),
		WithMockError(PluginMockError{
			bucketName: "aws_s3_err",
			objectKey:  "mock_object",
			errMsg:     "invalid credentials",
			errCode:    codes.PermissionDenied,
		}),
	)
	assert.NoError(err)

	client := NewWrappingPluginStorageClient(plg)

	secrets := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			"AWS_ACCESS_KEY_ID":     structpb.NewStringValue("access_key_id"),
			"AWS_SECRET_ACCESS_KEY": structpb.NewStringValue("secret_access_key"),
		},
	}

	tests := []struct {
		name        string
		request     *plgpb.GetObjectRequest
		expectedErr codes.Code
		expectedObj *storagePluginStorageInfo
	}{
		{
			name:        "missing request",
			expectedErr: codes.InvalidArgument,
		},
		{
			name:        "missing storage bucket",
			request:     &plgpb.GetObjectRequest{},
			expectedErr: codes.InvalidArgument,
		},
		{
			name: "missing secrets",
			request: &plgpb.GetObjectRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_mock",
				},
			},
			expectedErr: codes.InvalidArgument,
		},
		{
			name: "emtpy object key",
			request: &plgpb.GetObjectRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_mock",
					Secrets:    secrets,
				},
			},
			expectedErr: codes.InvalidArgument,
		},
		{
			name: "bucket not found",
			request: &plgpb.GetObjectRequest{
				Key: "mock_object",
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "invalid_bucket",
					Secrets:    secrets,
				},
			},
			expectedErr: codes.NotFound,
		},
		{
			name: "object not found",
			request: &plgpb.GetObjectRequest{
				Key: "invalid_object_key",
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_mock",
					Secrets:    secrets,
				},
			},
			expectedErr: codes.NotFound,
		},
		{
			name: "mocked error",
			request: &plgpb.GetObjectRequest{
				Key: "mock_object",
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_err",
					Secrets:    secrets,
				},
			},
			expectedErr: codes.PermissionDenied,
		},
		{
			name: "object retrieved",
			request: &plgpb.GetObjectRequest{
				Key: "mock_object",
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_mock",
					Secrets:    secrets,
				},
			},
			expectedObj: mockStorageMapData["aws_s3_mock"]["mock_object"],
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stream, err := client.GetObject(context.Background(), tt.request)
			if tt.expectedErr != codes.OK {
				assert.Error(err)
				s, ok := status.FromError(err)
				require.True(ok, "invalid error type")
				assert.Equal(s.Code(), tt.expectedErr)
				return
			}
			var actualData []byte
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					response, err := stream.Recv()
					if err == io.EOF {
						break
					}
					assert.NoError(err)
					require.NotNil(response)
					actualData = append(actualData, response.GetFileChunk()...)
				}
			}()
			wg.Wait()

			assert.NotEmpty(actualData)
			assert.NotNil(tt.expectedObj)
			assert.NotEmpty(tt.expectedObj.DataChunks)

			var expectedData []byte
			for _, chunk := range tt.expectedObj.DataChunks {
				expectedData = append(expectedData, chunk...)
			}
			assert.EqualValues(expectedData, actualData)
		})
	}
}

func TestLoopbackPutObject(t *testing.T) {
	require, assert := tr.New(t), ta.New(t)

	mockStorageMapData := map[BucketName]Bucket{
		"aws_s3_mock": {},
		"aws_s3_err":  {},
	}

	plg, err := NewLoopbackPlugin(
		WithMockBuckets(mockStorageMapData),
		WithMockError(PluginMockError{
			bucketName: "aws_s3_err",
			objectKey:  "mock_object",
			errMsg:     "invalid credentials",
			errCode:    codes.PermissionDenied,
		}),
	)
	assert.NoError(err)

	client := NewWrappingPluginStorageClient(plg)

	secrets := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			"AWS_ACCESS_KEY_ID":     structpb.NewStringValue("access_key_id"),
			"AWS_SECRET_ACCESS_KEY": structpb.NewStringValue("secret_access_key"),
		},
	}

	tests := []struct {
		name        string
		request     *plgpb.PutObjectRequest
		dataChunks  []Chunk
		expectedErr codes.Code
	}{
		{
			name: "missing request metadata",
			request: &plgpb.PutObjectRequest{
				Data: &plgpb.PutObjectRequest_Request{},
			},
			expectedErr: codes.InvalidArgument,
		},
		{
			name: "missing storage bucket",
			request: &plgpb.PutObjectRequest{
				Data: &plgpb.PutObjectRequest_Request{
					Request: &plgpb.PutObjectMetadata{},
				},
			},
			expectedErr: codes.InvalidArgument,
		},
		{
			name: "missing secrets",
			request: &plgpb.PutObjectRequest{
				Data: &plgpb.PutObjectRequest_Request{
					Request: &plgpb.PutObjectMetadata{
						Bucket: &storagebuckets.StorageBucket{
							BucketName: "aws_s3_mock",
						},
					},
				},
			},
			expectedErr: codes.InvalidArgument,
		},
		{
			name: "missing object key",
			request: &plgpb.PutObjectRequest{
				Data: &plgpb.PutObjectRequest_Request{
					Request: &plgpb.PutObjectMetadata{
						Bucket: &storagebuckets.StorageBucket{
							BucketName: "aws_s3_mock",
							Secrets:    secrets,
						},
					},
				},
			},
			expectedErr: codes.InvalidArgument,
		},
		{
			name: "empty object data",
			dataChunks: []Chunk{
				[]byte(""),
			},
			request: &plgpb.PutObjectRequest{
				Data: &plgpb.PutObjectRequest_Request{
					Request: &plgpb.PutObjectMetadata{
						Bucket: &storagebuckets.StorageBucket{
							BucketName: "aws_s3_mock",
							Secrets:    secrets,
						},
						Key: "mock_object",
					},
				},
			},
			expectedErr: codes.InvalidArgument,
		},
		{
			name: "bucket not found",
			dataChunks: []Chunk{
				[]byte("THIS IS A MOCKED OBJECT"),
			},
			request: &plgpb.PutObjectRequest{
				Data: &plgpb.PutObjectRequest_Request{
					Request: &plgpb.PutObjectMetadata{
						Bucket: &storagebuckets.StorageBucket{
							BucketName: "invalid_bucket",
							Secrets:    secrets,
						},
						Key: "mock_object",
					},
				},
			},
			expectedErr: codes.NotFound,
		},
		{
			name: "mock error",
			dataChunks: []Chunk{
				[]byte("THIS IS A MOCKED OBJECT"),
			},
			request: &plgpb.PutObjectRequest{
				Data: &plgpb.PutObjectRequest_Request{
					Request: &plgpb.PutObjectMetadata{
						Bucket: &storagebuckets.StorageBucket{
							BucketName: "aws_s3_err",
							Secrets:    secrets,
						},
						Key: "mock_object",
					},
				},
			},
			expectedErr: codes.PermissionDenied,
		},
		{
			name: "valid object",
			dataChunks: []Chunk{
				[]byte("THIS IS A MOCKED OBJECT"),
			},
			request: &plgpb.PutObjectRequest{
				Data: &plgpb.PutObjectRequest_Request{
					Request: &plgpb.PutObjectMetadata{
						Bucket: &storagebuckets.StorageBucket{
							BucketName: "aws_s3_mock",
							Secrets:    secrets,
						},
						Key: "mock_object",
					},
				},
			},
		},
		{
			name: "valid object with dir in key",
			dataChunks: []Chunk{
				[]byte("THIS IS A MOCKED OBJECT"),
			},
			request: &plgpb.PutObjectRequest{
				Data: &plgpb.PutObjectRequest_Request{
					Request: &plgpb.PutObjectMetadata{
						Bucket: &storagebuckets.StorageBucket{
							BucketName: "aws_s3_mock",
							Secrets:    secrets,
						},
						Key: "foo/bar/zoo/mocked_object",
					},
				},
			},
		},
		{
			name: "valid object w/ prefix",
			dataChunks: []Chunk{
				[]byte("THIS IS A MOCKED OBJECT"),
			},
			request: &plgpb.PutObjectRequest{
				Data: &plgpb.PutObjectRequest_Request{
					Request: &plgpb.PutObjectMetadata{
						Bucket: &storagebuckets.StorageBucket{
							BucketName:   "aws_s3_mock",
							BucketPrefix: "/filtered/",
							Secrets:      secrets,
						},
						Key: "mock_object",
					},
				},
			},
		},
		{
			name: "valid object w/ multiple chunks",
			dataChunks: []Chunk{
				[]byte("PART A: 1234567890"),
				[]byte("PART B: 0987654321"),
				[]byte("PART C: qwertyuiop"),
				[]byte("PART D: poiuytrewq"),
				[]byte("PART E: asdfghjkl"),
				[]byte("PART F: lkjhgfdsa"),
				[]byte("PART G: zxcvbnm"),
				[]byte("PART H: mnbvcxz"),
			},
			request: &plgpb.PutObjectRequest{
				Data: &plgpb.PutObjectRequest_Request{
					Request: &plgpb.PutObjectMetadata{
						Bucket: &storagebuckets.StorageBucket{
							BucketName: "aws_s3_mock",
							Secrets:    secrets,
						},
						Key: "multi_chunk_object",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stream, err := client.PutObject(context.Background())
			assert.NoError(err)
			assert.NotNil(stream)

			var objectData []byte
			var closeResponse *plgpb.PutObjectResponse
			var closeErr error
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				err = stream.Send(tt.request)
				assert.NoError(err)

				for _, chunk := range tt.dataChunks {
					objectData = append(objectData, chunk...)
					err = stream.Send(&plgpb.PutObjectRequest{
						Data: &plgpb.PutObjectRequest_FileChunk{
							FileChunk: chunk,
						},
					})
					assert.NoError(err)
				}

				closeResponse, closeErr = stream.CloseAndRecv()
			}()
			wg.Wait()

			if tt.expectedErr != codes.OK {
				assert.Error(closeErr)
				assert.Nil(closeResponse)
				s, ok := status.FromError(closeErr)
				require.True(ok, "invalid error type")
				assert.Equal(s.Code(), tt.expectedErr)
				return
			}

			assert.NoError(closeErr)
			require.NotNil(closeResponse)

			var actualObject *storagePluginStorageInfo
			objectPath := ObjectName(tt.request.GetRequest().GetBucket().GetBucketPrefix() + tt.request.GetRequest().GetKey())
			if obj, ok := mockStorageMapData[BucketName(tt.request.GetRequest().GetBucket().GetBucketName())][objectPath]; ok {
				actualObject = obj
			}
			require.NotNil(actualObject)
			assert.EqualValues(tt.dataChunks, actualObject.DataChunks)
			assert.NotEmpty(closeResponse.ChecksumSha_256)

			hash := sha256.New()
			_, err = io.Copy(hash, bytes.NewReader(objectData))
			require.NoError(err)
			assert.Equal(hash.Sum(nil), closeResponse.ChecksumSha_256)
		})
	}
}

func TestLoopbackStoragePlugin(t *testing.T) {
	require, assert := tr.New(t), ta.New(t)

	mockStorageMapData := map[BucketName]Bucket{
		"aws_s3_mock": {},
	}

	plg, err := NewLoopbackPlugin(WithMockBuckets(mockStorageMapData))
	assert.NoError(err)

	client := NewWrappingPluginStorageClient(plg)

	secrets := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			"ACCESS_KEY_ID":     structpb.NewStringValue("access_key_id"),
			"SECRET_ACCESS_KEY": structpb.NewStringValue("secret_access_key"),
		},
	}

	bucket := &storagebuckets.StorageBucket{
		BucketName:   "aws_s3_mock",
		BucketPrefix: "/filtered/path/",
		Secrets:      secrets,
	}
	objectData := []byte("THIS IS A MOCKED OBJECT")

	putObjectStream, err := client.PutObject(context.Background())
	assert.NoError(err)

	err = putObjectStream.Send(&plgpb.PutObjectRequest{
		Data: &plgpb.PutObjectRequest_Request{
			Request: &plgpb.PutObjectMetadata{
				Bucket: bucket,
				Key:    "dir1/mock_object",
			},
		},
	})
	assert.NoError(err)
	err = putObjectStream.Send(&plgpb.PutObjectRequest{
		Data: &plgpb.PutObjectRequest_FileChunk{
			FileChunk: objectData,
		},
	})
	assert.NoError(err)

	putResponse, err := putObjectStream.CloseAndRecv()
	require.NoError(err)
	require.NotNil(putResponse)
	assert.NotEmpty(putResponse.GetChecksumSha_256())
	hash := sha256.New()
	_, err = io.Copy(hash, bytes.NewReader(objectData))
	require.NoError(err)
	assert.EqualValues(hash.Sum(nil), putResponse.GetChecksumSha_256())

	// Check directory was created
	headResponse, err := plg.HeadObject(context.Background(), &plgpb.HeadObjectRequest{
		Bucket: bucket,
		Key:    "dir1/",
	})
	require.NoError(err)
	require.NotNil(headResponse)
	require.NotNil(headResponse.LastModified)
	require.Equal(int64(0), headResponse.ContentLength)

	headResponse, err = plg.HeadObject(context.Background(), &plgpb.HeadObjectRequest{
		Bucket: bucket,
		Key:    "dir1/mock_object",
	})
	require.NoError(err)
	require.NotNil(headResponse)
	require.NotNil(headResponse.LastModified)
	require.Equal(int64(len(objectData)), headResponse.ContentLength)

	getObjectStream, err := client.GetObject(context.Background(), &plgpb.GetObjectRequest{
		Bucket: bucket,
		Key:    "dir1/mock_object",
	})
	assert.NoError(err)

	var getObjectData []byte
	for {
		response, err := getObjectStream.Recv()
		if err == io.EOF {
			break
		}
		assert.NoError(err)
		require.NotNil(response)

		getObjectData = append(getObjectData, response.GetFileChunk()...)
	}
	require.NotEmpty(getObjectData)
	require.NotEmpty(objectData)
	assert.EqualValues(objectData, getObjectData)
}
