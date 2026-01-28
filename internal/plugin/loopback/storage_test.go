// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package loopback

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/storagebuckets"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	ta "github.com/stretchr/testify/assert"
	tr "github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestLoopbackOnCreateStorageBucket(t *testing.T) {
	require, assert := tr.New(t), ta.New(t)

	plg, err := NewLoopbackPlugin(
		WithMockBuckets(map[BucketName]Bucket{
			"aws_s3_mock": {},
			"aws_s3_err":  {},
		}),
		WithMockError(PluginMockError{
			BucketName: "aws_s3_err",
			ErrMsg:     "invalid credentials",
			ErrCode:    codes.PermissionDenied,
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
		name                 string
		request              *plgpb.OnCreateStorageBucketRequest
		expectedErr          codes.Code
		expectedStaticCreds  bool
		expectedDynamicCreds bool
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
			name: "missing attributes",
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
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
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
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
				},
			},
			expectedErr: codes.PermissionDenied,
		},
		{
			name: "error both credential types",
			request: &plgpb.OnCreateStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_mock",
					Secrets:    secrets,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint":              structpb.NewStringValue("0.0.0.0"),
							ConstDynamicCredentials: structpb.NewBoolValue(true),
						},
					},
				},
			},
			expectedErr: codes.InvalidArgument,
		},
		{
			name: "valid without credentials",
			request: &plgpb.OnCreateStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_mock",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
				},
			},
			expectedDynamicCreds: true,
		},
		{
			name: "valid with dynamic credentials",
			request: &plgpb.OnCreateStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_mock",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint":              structpb.NewStringValue("0.0.0.0"),
							ConstDynamicCredentials: structpb.NewBoolValue(true),
						},
					},
				},
			},
			expectedDynamicCreds: true,
		},
		{
			name: "valid with static credentials",
			request: &plgpb.OnCreateStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_mock",
					Secrets:    secrets,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
				},
			},
			expectedStaticCreds: true,
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

			if tt.expectedDynamicCreds {
				assert.Empty(response.GetPersisted().GetData().AsMap())
				return
			}

			if tt.expectedStaticCreds {
				assert.NotEmpty(response.GetPersisted().GetData().AsMap())
				assert.EqualValues(tt.request.GetBucket().GetSecrets().AsMap(), response.GetPersisted().GetData().AsMap())
				return
			}
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
			BucketName: "aws_s3_err",
			ErrMsg:     "invalid credentials",
			ErrCode:    codes.PermissionDenied,
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
	persisted := &storagebuckets.StorageBucketPersisted{
		Data: secrets,
	}

	tests := []struct {
		name                 string
		request              *plgpb.OnUpdateStorageBucketRequest
		expectedErr          codes.Code
		expectedStaticCreds  bool
		expectedDynamicCreds bool
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
			name: "missing attributes",
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
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
				},
				Persisted: persisted,
			},
			expectedErr: codes.NotFound,
		},
		{
			name: "mocked error",
			request: &plgpb.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_err",
					Secrets:    secrets,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
				},
				Persisted: persisted,
			},
			expectedErr: codes.PermissionDenied,
		},
		{
			name: "error both credential types",
			request: &plgpb.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_mock",
					Secrets:    secrets,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint":              structpb.NewStringValue("0.0.0.0"),
							ConstDynamicCredentials: structpb.NewBoolValue(true),
						},
					},
				},
			},
			expectedErr: codes.InvalidArgument,
		},
		{
			name: "valid without static credentials",
			request: &plgpb.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_mock",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
				},
			},
			expectedDynamicCreds: true,
		},
		{
			name: "valid with dynamic credentials attribute",
			request: &plgpb.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_mock",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint":              structpb.NewStringValue("0.0.0.0"),
							ConstDynamicCredentials: structpb.NewBoolValue(true),
						},
					},
				},
			},
			expectedDynamicCreds: true,
		},
		{
			name: "valid with both persisted and static credentials",
			request: &plgpb.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_mock",
					Secrets:    secrets,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
				},
				Persisted: persisted,
			},
			expectedStaticCreds: true,
		},
		{
			name: "valid with only persisted static credentials",
			request: &plgpb.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_mock",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
				},
				Persisted: persisted,
			},
			expectedStaticCreds: true,
		},
		{
			name: "valid with only static credentials",
			request: &plgpb.OnUpdateStorageBucketRequest{
				NewBucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_mock",
					Secrets:    secrets,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
				},
			},
			expectedStaticCreds: true,
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

			if tt.expectedDynamicCreds {
				assert.Empty(response.GetPersisted().GetData().AsMap())
				return
			}

			if tt.expectedStaticCreds {
				assert.NotEmpty(response.GetPersisted().GetData().AsMap())
				newSecrets := tt.request.GetNewBucket().GetSecrets()
				if newSecrets != nil && len(newSecrets.AsMap()) > 0 {
					assert.EqualValues(newSecrets.AsMap(), response.GetPersisted().GetData().AsMap())
					return
				}
				oldSecrets := tt.request.GetPersisted().GetData()
				if oldSecrets != nil && len(oldSecrets.AsMap()) > 0 {
					assert.EqualValues(oldSecrets.AsMap(), response.GetPersisted().GetData().AsMap())
					return
				}
				return
			}
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
	persisted := &storagebuckets.StorageBucketPersisted{
		Data: secrets,
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
			name: "missing attributes",
			request: &plgpb.OnDeleteStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_mock",
				},
			},
			expectedErr: codes.InvalidArgument,
		},
		{
			name: "valid without credentials",
			request: &plgpb.OnDeleteStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_mock",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
				},
			},
		},
		{
			name: "valid with credentials",
			request: &plgpb.OnDeleteStorageBucketRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_mock",
					Secrets:    secrets,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
				},
				Persisted: persisted,
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
			"aws_s3_mock":               {},
			"aws_s3_err":                {},
			"aws_s3_err_with_sbc_state": {},
		}),
		WithMockError(PluginMockError{
			BucketName: "aws_s3_err",
			ErrMsg:     "invalid credentials",
			ErrCode:    codes.PermissionDenied,
		}),
		WithMockError(PluginMockError{
			BucketName: "aws_s3_err_with_sbc_state",
			ErrMsg:     "invalid credentials",
			ErrCode:    codes.PermissionDenied,
			StorageBucketCredentialState: &plgpb.StorageBucketCredentialState{
				State: &plgpb.Permissions{
					Write: &plgpb.Permission{
						State:        plgpb.StateType_STATE_TYPE_ERROR,
						CheckedAt:    timestamppb.Now(),
						ErrorDetails: "invalid credentials",
					},
					Read: &plgpb.Permission{
						State:     plgpb.StateType_STATE_TYPE_OK,
						CheckedAt: timestamppb.Now(),
					},
					Delete: &plgpb.Permission{
						State:     plgpb.StateType_STATE_TYPE_OK,
						CheckedAt: timestamppb.Now(),
					},
				},
			},
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
		name             string
		request          *plgpb.ValidatePermissionsRequest
		expectedErr      codes.Code
		expectedSBCState *plgpb.StorageBucketCredentialState
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
			name: "missing attributes",
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
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
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
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
				},
			},
			expectedErr: codes.PermissionDenied,
		},
		{
			name: "valid without credentials",
			request: &plgpb.ValidatePermissionsRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_mock",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
				},
			},
		},
		{
			name: "valid with credentials",
			request: &plgpb.ValidatePermissionsRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_mock",
					Secrets:    secrets,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
				},
			},
		},
		{
			name: "mocked error with SBC state",
			request: &plgpb.ValidatePermissionsRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_err_with_sbc_state",
					Secrets:    secrets,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
				},
			},
			expectedErr: codes.PermissionDenied,
			expectedSBCState: &plgpb.StorageBucketCredentialState{
				State: &plgpb.Permissions{
					Write: &plgpb.Permission{
						State:        plgpb.StateType_STATE_TYPE_ERROR,
						CheckedAt:    timestamppb.Now(),
						ErrorDetails: "invalid credentials",
					},
					Read: &plgpb.Permission{
						State:     plgpb.StateType_STATE_TYPE_OK,
						CheckedAt: timestamppb.Now(),
					},
					Delete: &plgpb.Permission{
						State:     plgpb.StateType_STATE_TYPE_OK,
						CheckedAt: timestamppb.Now(),
					},
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

				if tt.expectedSBCState != nil {
					sbcState := parseStorageBucketCredentialStateFromError(err)
					require.NotNil(sbcState)
					assert.Equal(tt.expectedSBCState.State.Write.GetState(), sbcState.State.Write.GetState())
					assert.Equal(tt.expectedSBCState.State.Write.GetErrorDetails(), sbcState.State.Write.GetErrorDetails())

					assert.Equal(tt.expectedSBCState.State.Read.GetState(), sbcState.State.Read.GetState())
					assert.Equal(tt.expectedSBCState.State.Read.GetErrorDetails(), sbcState.State.Read.GetErrorDetails())

					assert.Equal(tt.expectedSBCState.State.Delete.GetState(), sbcState.State.Delete.GetState())
					assert.Equal(tt.expectedSBCState.State.Delete.GetErrorDetails(), sbcState.State.Delete.GetErrorDetails())
				}
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
			BucketName: "aws_s3_err",
			ObjectKey:  "mock_object",
			ErrMsg:     "invalid credentials",
			ErrCode:    codes.PermissionDenied,
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
			name: "missing attributes",
			request: &plgpb.HeadObjectRequest{
				Key: "mock_object",
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_mock",
				},
			},
			expectedErr: codes.InvalidArgument,
		},
		{
			name: "empty object key",
			request: &plgpb.HeadObjectRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_mock",
					Secrets:    secrets,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
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
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
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
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
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
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
				},
			},
			expectedErr: codes.PermissionDenied,
		},
		{
			name: "head retrieved without secrets",
			request: &plgpb.HeadObjectRequest{
				Key: "mock_object",
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_mock",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
				},
			},
			expectedObj: mockStorageMapData["aws_s3_mock"]["mock_object"],
		},
		{
			name: "head retrieved",
			request: &plgpb.HeadObjectRequest{
				Key: "mock_object",
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_mock",
					Secrets:    secrets,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
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
			BucketName: "aws_s3_err",
			ObjectKey:  "mock_object",
			ErrMsg:     "invalid credentials",
			ErrCode:    codes.PermissionDenied,
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
			name: "missing attributes",
			request: &plgpb.GetObjectRequest{
				Key: "mock_object",
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_mock",
				},
			},
			expectedErr: codes.InvalidArgument,
		},
		{
			name: "empty object key",
			request: &plgpb.GetObjectRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_mock",
					Secrets:    secrets,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
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
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
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
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
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
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
				},
			},
			expectedErr: codes.PermissionDenied,
		},
		{
			name: "with chunk size",
			request: &plgpb.GetObjectRequest{
				Key: "mock_object",
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_mock",
					Secrets:    secrets,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
				},
				ChunkSize: 3,
			},
			expectedObj: mockStorageMapData["aws_s3_mock"]["mock_object"],
		},
		{
			name: "object retrieved without secrets",
			request: &plgpb.GetObjectRequest{
				Key: "mock_object",
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_mock",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
				},
			},
			expectedObj: mockStorageMapData["aws_s3_mock"]["mock_object"],
		},
		{
			name: "object retrieved",
			request: &plgpb.GetObjectRequest{
				Key: "mock_object",
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "aws_s3_mock",
					Secrets:    secrets,
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
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
	require := tr.New(t)
	td := t.TempDir()

	mockStorageMapData := map[BucketName]Bucket{
		"object_store":     {},
		"object_store_err": {},
	}

	plg, err := NewLoopbackPlugin(
		WithMockBuckets(mockStorageMapData),
		WithMockError(PluginMockError{
			BucketName: "object_store_err",
			ObjectKey:  "mock_object",
			ErrMsg:     "invalid credentials",
			ErrCode:    codes.PermissionDenied,
		}),
	)
	require.NoError(err)
	require.NotNil(plg)

	client := NewWrappingPluginStorageClient(plg)

	tests := []struct {
		name            string
		request         *plgpb.PutObjectRequest
		file            *os.File
		expectedErr     codes.Code
		expectedContent string
	}{
		{
			name:        "missing-request",
			expectedErr: codes.InvalidArgument,
		},
		{
			name:        "missing-bucket",
			request:     &plgpb.PutObjectRequest{},
			expectedErr: codes.InvalidArgument,
		},
		{
			name: "missing attributes",

			expectedErr: codes.InvalidArgument,
		},
		{
			name: "missing-bucket-name",
			request: &plgpb.PutObjectRequest{
				Bucket: &storagebuckets.StorageBucket{
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
				},
			},
			expectedErr: codes.InvalidArgument,
		},
		{
			name: "missing-key",
			request: &plgpb.PutObjectRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "object_store",
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"SECRET_KEY_ID": structpb.NewStringValue("secret_key_id"),
						},
					},
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
				},
			},
			expectedErr: codes.InvalidArgument,
		},
		{
			name: "missing-path",
			request: &plgpb.PutObjectRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "object_store",
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"SECRET_KEY_ID": structpb.NewStringValue("secret_key_id"),
						},
					},
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
				},
				Key: "test-file",
			},
			expectedErr: codes.InvalidArgument,
		},
		{
			name: "file-not-found",
			request: &plgpb.PutObjectRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "object_store",
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"SECRET_KEY_ID": structpb.NewStringValue("secret_key_id"),
						},
					},
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
				},
				Key:  "test-file",
				Path: path.Join(td, "test-file"),
			},
			expectedErr: codes.InvalidArgument,
		},
		{
			name: "path-is-directory",
			request: &plgpb.PutObjectRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "object_store",
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"SECRET_KEY_ID": structpb.NewStringValue("secret_key_id"),
						},
					},
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
				},
				Key:  "test-directory",
				Path: path.Join(td, "test-directory"),
			},
			file: func() *os.File {
				err := os.Mkdir(path.Join(td, "test-directory"), fs.ModeAppend)
				require.NoError(err)
				return nil
			}(),
			expectedErr: codes.InvalidArgument,
		},
		{
			name: "bucket-not-found",
			request: &plgpb.PutObjectRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "object_store_dne",
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"SECRET_KEY_ID": structpb.NewStringValue("secret_key_id"),
						},
					},
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
				},
				Key:  "test-bucket-not-found",
				Path: path.Join(td, "test-bucket-not-found"),
			},
			file: func() *os.File {
				file, err := os.Create(path.Join(td, "test-bucket-not-found"))
				require.NoError(err)
				return file
			}(),
			expectedErr: codes.InvalidArgument,
		},
		{
			name: "mock-error",
			request: &plgpb.PutObjectRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "object_store_err",
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"SECRET_KEY_ID": structpb.NewStringValue("secret_key_id"),
						},
					},
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
				},
				Key:  "mock_object",
				Path: path.Join(td, "test-bucket-not-found"),
			},
			file: func() *os.File {
				file, err := os.Create(path.Join(td, "test-mock-error"))
				require.NoError(err)
				return file
			}(),
			expectedErr: codes.PermissionDenied,
		},
		{
			name: "empty-object-data",
			request: &plgpb.PutObjectRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "object_store",
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"SECRET_KEY_ID": structpb.NewStringValue("secret_key_id"),
						},
					},
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
				},
				Key:  "test-empty-object-data",
				Path: path.Join(td, "test-empty-object-data"),
			},
			file: func() *os.File {
				file, err := os.Create(path.Join(td, "test-empty-object-data"))
				require.NoError(err)
				require.NoError(file.Close())
				return file
			}(),
			expectedErr: codes.InvalidArgument,
		},
		{
			name: "valid object with dir in key",
			request: &plgpb.PutObjectRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "object_store",
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"SECRET_KEY_ID": structpb.NewStringValue("secret_key_id"),
						},
					},
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
				},
				Key:  "foo/bar/zoo/mocked_object",
				Path: path.Join(td, "test-valid-object-dir-in-key"),
			},
			file: func() *os.File {
				file, err := os.Create(path.Join(td, "test-valid-object-dir-in-key"))
				require.NoError(err)
				n, err := file.WriteString("TEST OBJ WITH DIR IN KEY!")
				require.NoError(err)
				require.Equal(len("TEST OBJ WITH DIR IN KEY!"), n)
				require.NoError(file.Close())
				return file
			}(),
			expectedContent: "TEST OBJ WITH DIR IN KEY!",
		},
		{
			name: "valid object without credentials",
			request: &plgpb.PutObjectRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName:   "object_store",
					BucketPrefix: "/filtered/",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
				},
				Key:  "mocked_object_no_credentials",
				Path: path.Join(td, "test-valid-without-credentials"),
			},
			file: func() *os.File {
				file, err := os.Create(path.Join(td, "test-valid-without-credentials"))
				require.NoError(err)
				n, err := file.WriteString("TEST OBJ WITH NO CREDENTIALS!")
				require.NoError(err)
				require.Equal(len("TEST OBJ WITH NO CREDENTIALS!"), n)
				require.NoError(file.Close())
				return file
			}(),
			expectedContent: "TEST OBJ WITH NO CREDENTIALS!",
		},
		{
			name: "valid object w/ prefix",
			request: &plgpb.PutObjectRequest{
				Bucket: &storagebuckets.StorageBucket{
					BucketName:   "object_store",
					BucketPrefix: "/filtered/",
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"SECRET_KEY_ID": structpb.NewStringValue("secret_key_id"),
						},
					},
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
				},
				Key:  "mocked_object",
				Path: path.Join(td, "test-valid-object-prefix"),
			},
			file: func() *os.File {
				file, err := os.Create(path.Join(td, "test-valid-object-prefix"))
				require.NoError(err)
				n, err := file.WriteString("TEST OBJ WITH PREFIX!")
				require.NoError(err)
				require.Equal(len("TEST OBJ WITH PREFIX!"), n)
				require.NoError(file.Close())
				return file
			}(),
			expectedContent: "TEST OBJ WITH PREFIX!",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := client.PutObject(context.Background(), tt.request)
			if tt.expectedErr != codes.OK {
				require.Error(err)
				require.Nil(resp)
				s, ok := status.FromError(err)
				require.True(ok, "invalid error type")
				require.Equal(s.Code(), tt.expectedErr)
				return
			}
			require.NoError(err)
			require.NotNil(resp)

			actualBucket, ok := plg.buckets[BucketName(tt.request.Bucket.BucketName)]
			require.True(ok)
			require.NotEmpty(actualBucket)
			actualObject, ok := actualBucket[ObjectName(path.Join(tt.request.Bucket.BucketPrefix, tt.request.Key))]
			require.True(ok)
			require.NotEmpty(actualObject)
			actualData := []byte{}
			for _, c := range actualObject.DataChunks {
				actualData = append(actualData, c...)
			}
			require.Equal(tt.expectedContent, string(actualData))

			hash := sha256.New()
			_, err = io.Copy(hash, bytes.NewReader(actualData))
			require.NoError(err)
			require.ElementsMatch(hash.Sum(nil), resp.ChecksumSha_256)
		})
	}
}

func TestLoopbackDeleteObjects(t *testing.T) {
	require := tr.New(t)

	now := time.Now()
	var zero int64 = 0
	mockStorageMapData := map[BucketName]Bucket{
		"object_store": {
			ObjectName("test-file-1"): &storagePluginStorageInfo{
				lastModified:  &now,
				contentLength: &zero,
				DataChunks:    []Chunk{},
			},
			ObjectName("test-file-2"): &storagePluginStorageInfo{
				lastModified:  &now,
				contentLength: &zero,
				DataChunks:    []Chunk{},
			},
			ObjectName("test-file-3"): &storagePluginStorageInfo{
				lastModified:  &now,
				contentLength: &zero,
				DataChunks:    []Chunk{},
			},
			ObjectName("abc/file-1"): &storagePluginStorageInfo{
				lastModified:  &now,
				contentLength: &zero,
				DataChunks:    []Chunk{},
			},
			ObjectName("abc/file-2"): &storagePluginStorageInfo{
				lastModified:  &now,
				contentLength: &zero,
				DataChunks:    []Chunk{},
			},
			ObjectName("abc/file-3"): &storagePluginStorageInfo{
				lastModified:  &now,
				contentLength: &zero,
				DataChunks:    []Chunk{},
			},
		},
		"object_store_err": {},
	}

	plg, err := NewLoopbackPlugin(
		WithMockBuckets(mockStorageMapData),
		WithMockError(PluginMockError{
			BucketName: "object_store_err",
			ObjectKey:  "mock_object",
			ErrMsg:     "invalid credentials",
			ErrCode:    codes.PermissionDenied,
		}),
	)
	require.NoError(err)
	require.NotNil(plg)

	client := NewWrappingPluginStorageClient(plg)

	tests := []struct {
		name        string
		request     *plgpb.DeleteObjectsRequest
		expected    *plgpb.DeleteObjectsResponse
		expectedErr string
		check       func() error
	}{
		{
			name: "valid delete object no recursive",
			request: &plgpb.DeleteObjectsRequest{
				KeyPrefix: "test-file-1",
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "object_store",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
				},
				Recursive: false,
			},
			expected: &plgpb.DeleteObjectsResponse{
				ObjectsDeleted: 1,
			},
			check: func() error {
				filename := "test-file-1"
				bucket, _ := mockStorageMapData["object_store"]
				_, ok := bucket[ObjectName(filename)]
				if ok {
					return fmt.Errorf("failed to delete object %s", filename)
				}
				return nil
			},
		}, {
			name: "valid delete objects recursive",
			request: &plgpb.DeleteObjectsRequest{
				KeyPrefix: "abc/",
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "object_store",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
				},
				Recursive: true,
			},
			expected: &plgpb.DeleteObjectsResponse{
				ObjectsDeleted: 3,
			},
			check: func() error {
				filenames := []string{
					"abc/file-1",
					"abc/file-2",
					"abc/file-3",
				}
				bucket, _ := mockStorageMapData["object_store"]
				for _, filename := range filenames {
					_, ok := bucket[ObjectName(filename)]
					if ok {
						return fmt.Errorf("failed to delete object %s", filename)
					}
				}
				return nil
			},
		}, {
			name: "valid delete objects none",
			request: &plgpb.DeleteObjectsRequest{
				KeyPrefix: "abcd/",
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "object_store",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
				},
				Recursive: true,
			},
			expected: &plgpb.DeleteObjectsResponse{
				ObjectsDeleted: 0,
			},
			check: func() error {
				return nil
			},
		}, {
			name: "delete objects object doesn't exist",
			request: &plgpb.DeleteObjectsRequest{
				KeyPrefix: "non-existent-object",
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "object_store",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
				},
				Recursive: false,
			},
			expected: &plgpb.DeleteObjectsResponse{
				ObjectsDeleted: 1,
			},
			check: func() error {
				return nil
			},
		}, {
			name: "delete objects bucket doesn't exist",
			request: &plgpb.DeleteObjectsRequest{
				KeyPrefix: "abc/",
				Bucket: &storagebuckets.StorageBucket{
					BucketName: "non-existent-bucket",
					Attributes: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"endpoint": structpb.NewStringValue("0.0.0.0"),
						},
					},
				},
				Recursive: false,
			},
			expectedErr: "loopback.(LoopbackStorage).deleteObjects: bucket not found",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := client.DeleteObjects(context.Background(), tt.request)
			if tt.expectedErr != "" {
				require.Error(err)
				require.Nil(resp)
				require.ErrorContains(err, tt.expectedErr)
				return
			}

			require.Equal(tt.expected, resp)
			require.NoError(tt.check())
		})
	}
}

func TestLoopbackStoragePlugin(t *testing.T) {
	td := t.TempDir()

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
	attributes := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			"endpoint": structpb.NewStringValue("0.0.0.0"),
		},
	}

	objectData := "THIS IS A MOCKED OBJECT"
	bucket := &storagebuckets.StorageBucket{
		BucketName:   "aws_s3_mock",
		BucketPrefix: "/filtered/path/",
		Secrets:      secrets,
		Attributes:   attributes,
	}

	file, err := os.Create(path.Join(td, "test-put-object"))
	require.NoError(err)
	n, err := file.WriteString(objectData)
	require.NoError(err)
	require.Equal(len(objectData), n)
	require.NoError(file.Close())

	putResponse, err := client.PutObject(
		context.Background(), &plgpb.PutObjectRequest{
			Bucket: bucket,
			Key:    "dir1/mock_object",
			Path:   path.Join(td, "test-put-object"),
		})
	assert.NoError(err)
	require.NotNil(putResponse)
	assert.NotEmpty(putResponse.GetChecksumSha_256())
	hash := sha256.New()
	_, err = io.Copy(hash, strings.NewReader(objectData))
	require.NoError(err)
	assert.EqualValues(hash.Sum(nil), putResponse.GetChecksumSha_256())

	headResponse, err := plg.HeadObject(context.Background(), &plgpb.HeadObjectRequest{
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

func parseStorageBucketCredentialStateFromError(err error) *plgpb.StorageBucketCredentialState {
	sbcState := &plgpb.StorageBucketCredentialState{
		State: &plgpb.Permissions{
			Write: &plgpb.Permission{
				State:     plgpb.StateType_STATE_TYPE_UNKNOWN,
				CheckedAt: timestamppb.Now(),
			},
			Read: &plgpb.Permission{
				State:     plgpb.StateType_STATE_TYPE_UNKNOWN,
				CheckedAt: timestamppb.Now(),
			},
			Delete: &plgpb.Permission{
				State:     plgpb.StateType_STATE_TYPE_UNKNOWN,
				CheckedAt: timestamppb.Now(),
			},
		},
	}

	// attempt to retrieve the StorageBucketCredentialState detail from the error.
	if st, ok := status.FromError(err); ok {
		for _, detail := range st.Details() {
			if statusDetail, ok := detail.(*plgpb.StorageBucketCredentialState); ok {
				sbcState = statusDetail
				break
			}
		}
	}

	return sbcState
}
