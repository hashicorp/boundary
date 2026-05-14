// Copyright IBM Corp. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package loopback

import (
	"testing"

	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/storagebuckets"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestPluginMockError_match(t *testing.T) {
	t.Parallel()

	testBucket := &storagebuckets.StorageBucket{
		BucketName:   "test-bucket",
		BucketPrefix: "test-prefix",
	}

	testBucketNoPrefix := &storagebuckets.StorageBucket{
		BucketName: "test-bucket",
	}

	tests := []struct {
		name      string
		mockError PluginMockError
		bucket    *storagebuckets.StorageBucket
		key       string
		method    Method
		expected  bool
	}{
		{
			name: "exact match with all fields",
			mockError: PluginMockError{
				BucketName:   "test-bucket",
				BucketPrefix: "test-prefix",
				ObjectKey:    "test-key",
				ErrMethod:    PutObject,
			},
			bucket:   testBucket,
			key:      "test-key",
			method:   PutObject,
			expected: true,
		},
		{
			name: "match with Any method",
			mockError: PluginMockError{
				BucketName:   "test-bucket",
				BucketPrefix: "test-prefix",
				ObjectKey:    "test-key",
				ErrMethod:    Any,
			},
			bucket:   testBucket,
			key:      "test-key",
			method:   GetObject,
			expected: true,
		},
		{
			name: "match with empty key (create/update/delete operations)",
			mockError: PluginMockError{
				BucketName:   "test-bucket",
				BucketPrefix: "test-prefix",
				ErrMethod:    OnCreateStorageBucket,
			},
			bucket:   testBucket,
			key:      "", // Empty key for bucket operations
			method:   OnCreateStorageBucket,
			expected: true,
		},
		{
			name: "match with path prefix",
			mockError: PluginMockError{
				BucketName:   "test-bucket",
				BucketPrefix: "test-prefix",
				ObjectKey:    "logs/session123/data.log", // Must match the key exactly
				ErrPath:      "logs/",                    // Path prefix also matches
				ErrMethod:    PutObject,
			},
			bucket:   testBucket,
			key:      "logs/session123/data.log",
			method:   PutObject,
			expected: true,
		},
		{
			name: "no match - different bucket name",
			mockError: PluginMockError{
				BucketName: "different-bucket",
				ErrMethod:  PutObject,
			},
			bucket:   testBucket,
			key:      "test-key",
			method:   PutObject,
			expected: false,
		},
		{
			name: "no match - different object key",
			mockError: PluginMockError{
				BucketName: "test-bucket",
				ObjectKey:  "different-key",
				ErrMethod:  PutObject,
			},
			bucket:   testBucket,
			key:      "test-key",
			method:   PutObject,
			expected: false,
		},
		{
			name: "no match - different method",
			mockError: PluginMockError{
				BucketName: "test-bucket",
				ObjectKey:  "test-key",
				ErrMethod:  GetObject,
			},
			bucket:   testBucket,
			key:      "test-key",
			method:   PutObject,
			expected: false,
		},
		{
			name: "no match - different bucket prefix",
			mockError: PluginMockError{
				BucketName:   "test-bucket",
				BucketPrefix: "different-prefix",
				ErrMethod:    PutObject,
			},
			bucket:   testBucket,
			key:      "test-key",
			method:   PutObject,
			expected: false,
		},
		{
			name: "no match - path prefix doesn't match",
			mockError: PluginMockError{
				BucketName: "test-bucket",
				ObjectKey:  "", // ObjectKey should be empty when using ErrPath
				ErrPath:    "logs/",
				ErrMethod:  PutObject,
			},
			bucket:   testBucketNoPrefix,
			key:      "data/session123/info.json",
			method:   PutObject,
			expected: false,
		},
		{
			name: "match - bucket with no prefix requirement",
			mockError: PluginMockError{
				BucketName: "test-bucket",
				ObjectKey:  "test-key",
				ErrMethod:  PutObject,
			},
			bucket:   testBucketNoPrefix,
			key:      "test-key",
			method:   PutObject,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.mockError.match(tt.bucket, tt.key, tt.method)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPluginMockPutObjectResponse_match(t *testing.T) {
	t.Parallel()

	testBucket := &storagebuckets.StorageBucket{
		BucketName:   "test-bucket",
		BucketPrefix: "test-prefix",
	}

	testBucketNoPrefix := &storagebuckets.StorageBucket{
		BucketName: "test-bucket",
	}

	tests := []struct {
		name         string
		mockResponse PluginMockPutObjectResponse
		bucket       *storagebuckets.StorageBucket
		key          string
		expected     bool
	}{
		{
			name: "exact match with all fields",
			mockResponse: PluginMockPutObjectResponse{
				BucketName:   "test-bucket",
				BucketPrefix: "test-prefix",
				ObjectKey:    "test-key",
			},
			bucket:   testBucket,
			key:      "test-key",
			expected: true,
		},
		{
			name: "no match - different bucket name",
			mockResponse: PluginMockPutObjectResponse{
				BucketName: "different-bucket",
				ObjectKey:  "test-key",
			},
			bucket:   testBucket,
			key:      "test-key",
			expected: false,
		},
		{
			name: "no match - different object key",
			mockResponse: PluginMockPutObjectResponse{
				BucketName: "test-bucket",
				ObjectKey:  "different-key",
			},
			bucket:   testBucket,
			key:      "test-key",
			expected: false,
		},
		{
			name: "no match - different bucket prefix",
			mockResponse: PluginMockPutObjectResponse{
				BucketName:   "test-bucket",
				BucketPrefix: "different-prefix",
				ObjectKey:    "test-key",
			},
			bucket:   testBucket,
			key:      "test-key",
			expected: false,
		},
		{
			name: "match - bucket with no prefix requirement",
			mockResponse: PluginMockPutObjectResponse{
				BucketName: "test-bucket",
				ObjectKey:  "test-key",
			},
			bucket:   testBucketNoPrefix,
			key:      "test-key",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.mockResponse.match(tt.bucket, tt.key)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetTestOpts(t *testing.T) {
	t.Parallel()

	t.Run("default options", func(t *testing.T) {
		opts, err := getTestOpts()
		require.NoError(t, err)

		expected := TestOptions{
			withChunkSize: 8,
		}
		assert.Equal(t, expected.withChunkSize, opts.withChunkSize)
		assert.Nil(t, opts.withMockBuckets)
		assert.Empty(t, opts.withMockError)
		assert.Empty(t, opts.withMockPutObjectResponse)
	})

	t.Run("with mock buckets", func(t *testing.T) {
		mockBuckets := map[BucketName]Bucket{
			"test-bucket": make(Bucket),
		}

		opts, err := getTestOpts(WithMockBuckets(mockBuckets))
		require.NoError(t, err)

		assert.Equal(t, mockBuckets, opts.withMockBuckets)
	})

	t.Run("with mock error", func(t *testing.T) {
		mockError := PluginMockError{
			BucketName: "test-bucket",
			ErrMsg:     "test error",
			ErrCode:    codes.Internal,
			ErrMethod:  PutObject,
		}

		opts, err := getTestOpts(WithMockError(mockError))
		require.NoError(t, err)

		require.Len(t, opts.withMockError, 1)
		assert.Equal(t, mockError, opts.withMockError[0])
	})

	t.Run("with multiple mock errors", func(t *testing.T) {
		mockError1 := PluginMockError{
			BucketName: "test-bucket-1",
			ErrMsg:     "test error 1",
			ErrCode:    codes.Internal,
			ErrMethod:  PutObject,
		}
		mockError2 := PluginMockError{
			BucketName: "test-bucket-2",
			ErrMsg:     "test error 2",
			ErrCode:    codes.NotFound,
			ErrMethod:  GetObject,
		}

		opts, err := getTestOpts(
			WithMockError(mockError1),
			WithMockError(mockError2),
		)
		require.NoError(t, err)

		require.Len(t, opts.withMockError, 2)
		assert.Equal(t, mockError1, opts.withMockError[0])
		assert.Equal(t, mockError2, opts.withMockError[1])
	})

	t.Run("with mock put object response", func(t *testing.T) {
		mockResponse := PluginMockPutObjectResponse{
			BucketName: "test-bucket",
			ObjectKey:  "test-key",
			Response: &plgpb.PutObjectResponse{
				ChecksumSha_256: []byte("test-checksum"),
			},
		}

		opts, err := getTestOpts(WithMockPutObjectResponse(mockResponse))
		require.NoError(t, err)

		require.Len(t, opts.withMockPutObjectResponse, 1)
		assert.Equal(t, mockResponse, opts.withMockPutObjectResponse[0])
	})

	t.Run("with custom chunk size", func(t *testing.T) {
		customChunkSize := 16

		opts, err := getTestOpts(WithChunkSize(customChunkSize))
		require.NoError(t, err)

		assert.Equal(t, customChunkSize, opts.withChunkSize)
	})

	t.Run("with all options combined", func(t *testing.T) {
		mockBuckets := map[BucketName]Bucket{
			"test-bucket": make(Bucket),
		}
		mockError := PluginMockError{
			BucketName: "test-bucket",
			ErrMsg:     "test error",
			ErrCode:    codes.Internal,
			ErrMethod:  PutObject,
		}
		mockResponse := PluginMockPutObjectResponse{
			BucketName: "test-bucket",
			ObjectKey:  "test-key",
			Response: &plgpb.PutObjectResponse{
				ChecksumSha_256: []byte("test-checksum"),
			},
		}
		customChunkSize := 32

		opts, err := getTestOpts(
			WithMockBuckets(mockBuckets),
			WithMockError(mockError),
			WithMockPutObjectResponse(mockResponse),
			WithChunkSize(customChunkSize),
		)
		require.NoError(t, err)

		assert.Equal(t, mockBuckets, opts.withMockBuckets)
		require.Len(t, opts.withMockError, 1)
		assert.Equal(t, mockError, opts.withMockError[0])
		require.Len(t, opts.withMockPutObjectResponse, 1)
		assert.Equal(t, mockResponse, opts.withMockPutObjectResponse[0])
		assert.Equal(t, customChunkSize, opts.withChunkSize)
	})
}

func TestGetDefaultTestOptions(t *testing.T) {
	t.Parallel()

	opts := getDefaultTestOptions()

	assert.Equal(t, 8, opts.withChunkSize)
	assert.Nil(t, opts.withMockBuckets)
	assert.Empty(t, opts.withMockError)
	assert.Empty(t, opts.withMockPutObjectResponse)
}

func TestMethod_Constants(t *testing.T) {
	t.Parallel()

	// Test that Method constants have expected values
	assert.Equal(t, Method(0), Any)
	assert.Equal(t, Method(1), OnCreateStorageBucket)
	assert.Equal(t, Method(2), OnUpdateStorageBucket)
	assert.Equal(t, Method(3), OnDeleteStorageBucket)
	assert.Equal(t, Method(4), ValidatePermissions)
	assert.Equal(t, Method(5), HeadObject)
	assert.Equal(t, Method(6), GetObject)
	assert.Equal(t, Method(7), PutObject)
	assert.Equal(t, Method(8), DeleteObjects)
}

func TestPluginMockError_ComplexScenarios(t *testing.T) {
	t.Parallel()

	t.Run("storage bucket credential state scenarios", func(t *testing.T) {
		bucket := &storagebuckets.StorageBucket{
			BucketName: "test-bucket",
		}

		credentialState := &plgpb.StorageBucketCredentialState{
			State: &plgpb.Permissions{
				Write: &plgpb.Permission{
					State: plgpb.StateType_STATE_TYPE_ERROR,
				},
			},
		}

		mockError := PluginMockError{
			BucketName:                   "test-bucket",
			ErrMethod:                    ValidatePermissions,
			StorageBucketCredentialState: credentialState,
		}

		result := mockError.match(bucket, "", ValidatePermissions)
		assert.True(t, result)
	})

	t.Run("path-based error matching", func(t *testing.T) {
		bucket := &storagebuckets.StorageBucket{
			BucketName: "test-bucket",
		}

		tests := []struct {
			name      string
			errPath   string
			objectKey string
			key       string
			expected  bool
		}{
			{
				name:      "exact path match",
				errPath:   "sessions/",
				objectKey: "sessions/sr_123/data.log",
				key:       "sessions/sr_123/data.log",
				expected:  true,
			},
			{
				name:      "nested path match",
				errPath:   "sessions/sr_123/",
				objectKey: "sessions/sr_123/connections/cr_456/data.log",
				key:       "sessions/sr_123/connections/cr_456/data.log",
				expected:  true,
			},
			{
				name:      "no path match",
				errPath:   "sessions/",
				objectKey: "recordings/sr_123/data.log",
				key:       "recordings/sr_123/data.log",
				expected:  false,
			},
			{
				name:      "path match but different object key",
				errPath:   "sessions/",
				objectKey: "sessions/file1.log",
				key:       "sessions/file2.log",
				expected:  false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				mockError := PluginMockError{
					BucketName: "test-bucket",
					ObjectKey:  tt.objectKey,
					ErrPath:    tt.errPath,
					ErrMethod:  PutObject,
				}

				result := mockError.match(bucket, tt.key, PutObject)
				assert.Equal(t, tt.expected, result)
			})
		}
	})

	t.Run("path-based matching with empty key (bucket operations)", func(t *testing.T) {
		bucket := &storagebuckets.StorageBucket{
			BucketName: "test-bucket",
		}

		t.Run("empty path matches bucket operations", func(t *testing.T) {
			mockError := PluginMockError{
				BucketName: "test-bucket",
				ObjectKey:  "",
				ErrPath:    "", // Empty path works with empty key
				ErrMethod:  OnCreateStorageBucket,
			}

			// Empty key for bucket operations (create/update/delete)
			result := mockError.match(bucket, "", OnCreateStorageBucket)
			assert.True(t, result)
		})

		t.Run("non-empty path does not match empty key", func(t *testing.T) {
			mockError := PluginMockError{
				BucketName: "test-bucket",
				ObjectKey:  "",
				ErrPath:    "some/path/", // Non-empty path won't match empty key
				ErrMethod:  OnCreateStorageBucket,
			}

			// Empty key for bucket operations - should not match non-empty path
			result := mockError.match(bucket, "", OnCreateStorageBucket)
			assert.False(t, result)
		})
	})
}

func TestTestOptions_EdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("zero chunk size", func(t *testing.T) {
		opts, err := getTestOpts(WithChunkSize(0))
		require.NoError(t, err)
		assert.Equal(t, 0, opts.withChunkSize)
	})

	t.Run("negative chunk size", func(t *testing.T) {
		opts, err := getTestOpts(WithChunkSize(-1))
		require.NoError(t, err)
		assert.Equal(t, -1, opts.withChunkSize)
	})

	t.Run("empty mock buckets map", func(t *testing.T) {
		emptyBuckets := make(map[BucketName]Bucket)
		opts, err := getTestOpts(WithMockBuckets(emptyBuckets))
		require.NoError(t, err)
		assert.NotNil(t, opts.withMockBuckets)
		assert.Empty(t, opts.withMockBuckets)
	})

	t.Run("nil mock buckets map", func(t *testing.T) {
		opts, err := getTestOpts(WithMockBuckets(nil))
		require.NoError(t, err)
		assert.Nil(t, opts.withMockBuckets)
	})
}
