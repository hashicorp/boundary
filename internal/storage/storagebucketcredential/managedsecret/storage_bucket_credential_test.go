// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package managedsecret

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/storage/plugin/store"
	"github.com/hashicorp/boundary/internal/storage/storagebucketcredential"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

func Test_HmacSecrets(t *testing.T) {
	// emptyPersistedData represents the data returned by the AWS plugin when using an unknown or dynamic credential type.
	emptyPersistedData, err := structpb.NewStruct(map[string]any{})
	require.NoError(t, err)
	testEmptySecret, err := proto.Marshal(emptyPersistedData)
	require.NoError(t, err)

	wrapper := db.TestWrapper(t)
	tests := []struct {
		name           string
		cipher         wrapping.Wrapper
		sbc            *StorageBucketCredential
		expectedErrMsg string
	}{
		{
			name:           "missing-cipher",
			expectedErrMsg: "missing cipher",
		},
		{
			name: "nil-secret",
			sbc: &StorageBucketCredential{
				StorageBucketCredentialManagedSecret: &store.StorageBucketCredentialManagedSecret{},
			},
			cipher:         wrapper,
			expectedErrMsg: "failed to hmac secrets: encryption issue: error #300: plugin.hmacField: unknown, unknown: error #0: crypto.HmacSha256: missing data: Invalid parameter",
		},
		{
			name: "empty-secret",
			sbc: &StorageBucketCredential{
				StorageBucketCredentialManagedSecret: &store.StorageBucketCredentialManagedSecret{
					Secrets: []byte{},
				},
			},
			cipher: wrapper,
		},
		{
			name: "aws-empty-persisted-data",
			sbc: &StorageBucketCredential{
				StorageBucketCredentialManagedSecret: &store.StorageBucketCredentialManagedSecret{
					Secrets: testEmptySecret,
				},
			},
			cipher: wrapper,
		},
		{
			name: "valid",
			sbc: &StorageBucketCredential{
				StorageBucketCredentialManagedSecret: &store.StorageBucketCredentialManagedSecret{
					Secrets: []byte("hello world"),
				},
			},
			cipher: wrapper,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)

			actualHmac, err := tt.sbc.HmacSecrets(context.Background(), tt.cipher)
			if tt.expectedErrMsg != "" {
				require.Error(err)
				assert.ErrorContains(err, tt.expectedErrMsg)
				assert.Empty(actualHmac)
				return
			}
			require.NoError(err)
			assert.NotEmpty(actualHmac)
		})
	}
}

func Test_Encrypt(t *testing.T) {
	// emptyPersistedData represents the data returned by the AWS plugin when using an unknown or dynamic credential type.
	emptyPersistedData, err := structpb.NewStruct(map[string]any{})
	require.NoError(t, err)
	testEmptySecret, err := proto.Marshal(emptyPersistedData)
	require.NoError(t, err)

	wrapper := db.TestWrapper(t)
	tests := []struct {
		name           string
		cipher         wrapping.Wrapper
		sbc            *StorageBucketCredential
		expectedErrMsg string
	}{
		{
			name:           "missing-cipher",
			expectedErrMsg: "missing cipher",
		},
		{
			name: "nil-secret",
			sbc: &StorageBucketCredential{
				StorageBucketCredentialManagedSecret: &store.StorageBucketCredentialManagedSecret{},
			},
			cipher:         wrapper,
			expectedErrMsg: "error occurred during encrypt, encryption issue: error #300: plaintext byte slice is nil",
		},
		{
			name: "empty-secret",
			sbc: &StorageBucketCredential{
				StorageBucketCredentialManagedSecret: &store.StorageBucketCredentialManagedSecret{
					Secrets: []byte{},
				},
			},
			cipher: wrapper,
		},
		{
			name: "aws-empty-persisted-data",
			sbc: &StorageBucketCredential{
				StorageBucketCredentialManagedSecret: &store.StorageBucketCredentialManagedSecret{
					Secrets: testEmptySecret,
				},
			},
			cipher: wrapper,
		},
		{
			name: "valid",
			sbc: &StorageBucketCredential{
				StorageBucketCredentialManagedSecret: &store.StorageBucketCredentialManagedSecret{
					Secrets: []byte("hello world"),
				},
			},
			cipher: wrapper,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)

			err := tt.sbc.Encrypt(context.Background(), tt.cipher)
			if tt.expectedErrMsg != "" {
				require.Error(err)
				assert.ErrorContains(err, tt.expectedErrMsg)
				if tt.sbc != nil {
					assert.Empty(tt.sbc.GetCtSecrets())
					assert.Empty(tt.sbc.GetKeyId())
				}
				return
			}
			require.NoError(err)
			assert.NotEmpty(tt.sbc.GetCtSecrets())
			assert.NotEmpty(tt.sbc.GetKeyId())
		})
	}
}

func Test_Decrypt(t *testing.T) {
	// emptyPersistedData represents the data returned by the AWS plugin when using an unknown or dynamic credential type.
	emptyPersistedData, err := structpb.NewStruct(map[string]any{})
	require.NoError(t, err)
	testEmptySecret, err := proto.Marshal(emptyPersistedData)
	require.NoError(t, err)

	wrapper := db.TestWrapper(t)
	tests := []struct {
		name           string
		cipher         wrapping.Wrapper
		sbc            *StorageBucketCredential
		expectedSecret []byte
		expectedErrMsg string
	}{
		{
			name:           "missing-cipher",
			expectedErrMsg: "missing cipher",
		},
		{
			name: "nil-ctsecret",
			sbc: &StorageBucketCredential{
				StorageBucketCredentialManagedSecret: &store.StorageBucketCredentialManagedSecret{},
			},
			cipher:         wrapper,
			expectedErrMsg: "error occurred during decrypt, encryption issue: error #301: ciphertext pointer is nil",
		},
		{
			name: "empty-ctsecret",
			sbc: func() *StorageBucketCredential {
				sbc := &StorageBucketCredential{
					StorageBucketCredentialManagedSecret: &store.StorageBucketCredentialManagedSecret{
						Secrets: []byte{},
					},
				}
				require.NoError(t, sbc.Encrypt(context.Background(), wrapper))
				return sbc
			}(),
			cipher:         wrapper,
			expectedSecret: []byte(nil),
		},
		{
			name: "aws-empty-persisted-data",
			sbc: func() *StorageBucketCredential {
				sbc := &StorageBucketCredential{
					StorageBucketCredentialManagedSecret: &store.StorageBucketCredentialManagedSecret{
						Secrets: testEmptySecret,
					},
				}
				require.NoError(t, sbc.Encrypt(context.Background(), wrapper))
				return sbc
			}(),
			cipher:         wrapper,
			expectedSecret: []byte(nil),
		},
		{
			name: "valid",
			sbc: func() *StorageBucketCredential {
				sbc := &StorageBucketCredential{
					StorageBucketCredentialManagedSecret: &store.StorageBucketCredentialManagedSecret{
						Secrets: []byte("hello world"),
					},
				}
				require.NoError(t, sbc.Encrypt(context.Background(), wrapper))
				return sbc
			}(),
			cipher:         wrapper,
			expectedSecret: []byte("hello world"),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)

			err := tt.sbc.Decrypt(context.Background(), tt.cipher)
			if tt.expectedErrMsg != "" {
				require.Error(err)
				assert.ErrorContains(err, tt.expectedErrMsg)
				if tt.sbc != nil {
					assert.Empty(tt.sbc.GetCtSecrets())
					assert.Empty(tt.sbc.GetSecrets())
				}
				return
			}
			require.NoError(err)
			assert.Empty(tt.sbc.GetCtSecrets())
			assert.Equal(tt.expectedSecret, tt.sbc.GetSecrets())
		})
	}
}

func Test_ToPersisted(t *testing.T) {
	secret := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			"AWS_ACCESS_KEY_ID":     structpb.NewStringValue("access_key_id"),
			"AWS_SECRET_ACCESS_KEY": structpb.NewStringValue("secret_access_key"),
		},
	}
	testByteSecret, err := proto.Marshal(secret)
	require.NoError(t, err)
	tests := []struct {
		name           string
		sbc            *StorageBucketCredential
		expectedErrMsg string
	}{
		{
			name: "nil-secret",
			sbc: &StorageBucketCredential{
				StorageBucketCredentialManagedSecret: &store.StorageBucketCredentialManagedSecret{},
			},
			expectedErrMsg: "secret data not populated",
		},
		{
			name: "valid",
			sbc: &StorageBucketCredential{
				StorageBucketCredentialManagedSecret: &store.StorageBucketCredentialManagedSecret{
					Secrets: testByteSecret,
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)

			actualPersistedData, err := tt.sbc.ToPersisted(context.Background())
			if tt.expectedErrMsg != "" {
				require.Error(err)
				assert.ErrorContains(err, tt.expectedErrMsg)
				return
			}
			require.NoError(err)
			require.NotNil(actualPersistedData)
			require.NotNil(actualPersistedData.GetData())
			actualSecret := actualPersistedData.GetData().GetFields()
			assert.NotEmpty(actualSecret)
			assert.Len(actualSecret, len(secret.GetFields()))
			for key, expectedValue := range secret.GetFields() {
				actualValue, ok := actualSecret[key]
				require.True(ok)
				require.Equal(expectedValue.GetKind(), actualValue.GetKind())
				require.Equal(expectedValue.GetStringValue(), actualValue.GetStringValue())
			}
		})
	}
}

func Test_NewStorageBucketCredential(t *testing.T) {
	wrapper := db.TestWrapper(t)
	testKeyId, err := wrapper.KeyId(context.Background())
	require.NoError(t, err)
	tests := []struct {
		name            string
		storageBucketId string
		opts            []storagebucketcredential.Option
		expectedKeyId   string
		expectedErrMsg  string
	}{
		{
			name:           "missing-storage-bucket-id",
			expectedErrMsg: "missing storage bucket id",
		},
		{
			name:            "nil secret",
			storageBucketId: "sb_1234567890",
			expectedErrMsg:  "missing secret",
		},
		{
			name:            "empty secret",
			storageBucketId: "sb_1234567890",
			opts: []storagebucketcredential.Option{
				storagebucketcredential.WithSecret(&structpb.Struct{
					Fields: make(map[string]*structpb.Value),
				}),
			},
			expectedErrMsg: "empty secret",
		},
		{
			name:            "valid",
			storageBucketId: "sb_1234567890",
			opts: []storagebucketcredential.Option{
				storagebucketcredential.WithSecret(&structpb.Struct{
					Fields: map[string]*structpb.Value{
						"hello": structpb.NewStringValue("world"),
					},
				}),
			},
		},
		{
			name:            "valid-with-key",
			storageBucketId: "sb_1234567890",
			opts: []storagebucketcredential.Option{
				storagebucketcredential.WithSecret(&structpb.Struct{
					Fields: map[string]*structpb.Value{
						"hello": structpb.NewStringValue("world"),
					},
				}),
				storagebucketcredential.WithKeyId(testKeyId),
			},
			expectedKeyId: testKeyId,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)
			sbc := sbcHooks{}
			actualSBC, err := sbc.NewStorageBucketCredential(context.Background(), tt.storageBucketId, tt.opts...)
			if tt.expectedErrMsg != "" {
				require.Error(err)
				assert.Nil(actualSBC)
				assert.ErrorContains(err, tt.expectedErrMsg)
				return
			}
			require.NoError(err)
			require.NotNil(actualSBC)
			assert.NotEmpty(actualSBC.GetSecrets())
			assert.Equal(tt.storageBucketId, actualSBC.GetStorageBucketId())
			assert.Empty(actualSBC.GetPrivateId())
			assert.Empty(actualSBC.GetCtSecrets())
			if tt.expectedKeyId != "" {
				assert.Equal(tt.expectedKeyId, actualSBC.GetKeyId())
			} else {
				assert.Empty(actualSBC.GetKeyId())
			}
		})
	}
}
