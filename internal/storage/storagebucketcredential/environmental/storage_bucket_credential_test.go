// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package environmental

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/storage/plugin/store"
	"github.com/hashicorp/boundary/internal/storage/storagebucketcredential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func Test_HmacSecrets(t *testing.T) {
	wrapper := db.TestWrapper(t)
	sbc := &StorageBucketCredential{
		StorageBucketCredentialEnvironmental: &store.StorageBucketCredentialEnvironmental{},
	}
	acutalHmac, err := sbc.HmacSecrets(context.Background(), wrapper)
	require.Error(t, err)
	require.ErrorContains(t, err, "HmacSecrets not implemented")
	require.Empty(t, acutalHmac)
}

func Test_Encrypt(t *testing.T) {
	wrapper := db.TestWrapper(t)
	sbc := &StorageBucketCredential{
		StorageBucketCredentialEnvironmental: &store.StorageBucketCredentialEnvironmental{},
	}
	err := sbc.Encrypt(context.Background(), wrapper)
	require.Error(t, err)
	require.ErrorContains(t, err, "Encrypt not implemented")
}

func Test_Decrypt(t *testing.T) {
	wrapper := db.TestWrapper(t)
	sbc := &StorageBucketCredential{
		StorageBucketCredentialEnvironmental: &store.StorageBucketCredentialEnvironmental{},
	}
	err := sbc.Decrypt(context.Background(), wrapper)
	require.Error(t, err)
	require.ErrorContains(t, err, "Decrypt not implemented")
}

func Test_ToPersisted(t *testing.T) {
	sbc := &StorageBucketCredential{
		StorageBucketCredentialEnvironmental: &store.StorageBucketCredentialEnvironmental{},
	}
	actualPersistedData, err := sbc.ToPersisted(context.Background())
	require.Error(t, err)
	require.ErrorContains(t, err, "ToPersisted not implemented")
	require.Nil(t, actualPersistedData)
}

func Test_NewStorageBucketCredential(t *testing.T) {
	wrapper := db.TestWrapper(t)
	testKeyId, err := wrapper.KeyId(context.Background())
	require.NoError(t, err)
	tests := []struct {
		name            string
		storageBucketId string
		opts            []storagebucketcredential.Option
		expectedErrMsg  string
	}{
		{
			name:           "missing-storage-bucket-id",
			expectedErrMsg: "missing storage bucket id",
		},
		{
			name:            "ignore-secrets",
			storageBucketId: "sb_1234567890",
			opts: []storagebucketcredential.Option{
				storagebucketcredential.WithSecret(&structpb.Struct{
					Fields: make(map[string]*structpb.Value),
				}),
			},
		},
		{
			name:            "ignore-key",
			storageBucketId: "sb_1234567890",
			opts: []storagebucketcredential.Option{
				storagebucketcredential.WithKeyId(testKeyId),
			},
		},
		{
			name:            "valid",
			storageBucketId: "sb_1234567890",
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
			assert.Equal(tt.storageBucketId, actualSBC.GetStorageBucketId())
			assert.Empty(actualSBC.GetPrivateId())
			assert.Empty(actualSBC.GetSecrets())
			assert.Empty(actualSBC.GetCtSecrets())
			assert.Empty(actualSBC.GetKeyId())
		})
	}
}
