// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2b"
)

func TestToken_New(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)

	kkms := kms.TestKms(t, conn, wrapper)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cs := TestCredentialStores(t, conn, wrapper, prj.PublicId, 1)[0]

	type args struct {
		storeId    string
		token      TokenSecret
		accessor   []byte
		expiration time.Duration
	}

	hmac := func(t, a []byte) []byte {
		key := blake2b.Sum256(a)
		mac := hmac.New(sha256.New, key[:])
		_, _ = mac.Write(t)
		return mac.Sum(nil)
	}

	tests := []struct {
		name    string
		args    args
		want    *Token
		wantErr bool
	}{
		{
			name: "blank-store-id",
			args: args{
				storeId:    "",
				token:      TokenSecret("token"),
				accessor:   []byte("accessor"),
				expiration: 5 * time.Minute,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "missing-token",
			args: args{
				storeId:    cs.PublicId,
				accessor:   []byte("accessor"),
				expiration: 5 * time.Minute,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "missing-accessor",
			args: args{
				storeId:    cs.PublicId,
				token:      TokenSecret("token"),
				expiration: 5 * time.Minute,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "missing-expiration",
			args: args{
				storeId:  cs.PublicId,
				token:    TokenSecret("token"),
				accessor: []byte("accessor"),
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				storeId:    cs.PublicId,
				token:      TokenSecret("token"),
				accessor:   []byte("accessor"),
				expiration: 5 * time.Minute,
			},
			want: &Token{
				Token: &store.Token{
					StoreId:   cs.PublicId,
					Token:     []byte("token"),
					TokenHmac: hmac([]byte("token"), []byte("accessor")),
					Status:    string(CurrentToken),
				},
				expiration: 5 * time.Minute,
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			ctx := context.Background()
			databaseWrapper, err := kkms.GetWrapper(ctx, prj.PublicId, kms.KeyPurposeDatabase)
			require.NoError(err)
			require.NotNil(databaseWrapper)

			got, err := newToken(ctx, tt.args.storeId, tt.args.token, tt.args.accessor, tt.args.expiration)
			if tt.wantErr {
				assert.Error(err)
				require.Nil(got)
				return
			}
			require.NoError(err)
			require.NotNil(got)

			want := tt.want
			assert.Empty(got.CtToken)
			assert.Equal(want, got)

			require.NoError(got.encrypt(ctx, databaseWrapper))
			require.NoError(got.decrypt(ctx, databaseWrapper))
		})
	}
}

func subtract(t *testing.T, startTime, endTime *timestamp.Timestamp) time.Duration {
	t.Helper()
	require := require.New(t)
	require.NotNil(startTime, "startTime nil")
	require.NotNil(endTime, "endTime nil")

	a, b := startTime.GetTimestamp().AsTime(), endTime.GetTimestamp().AsTime()
	if b.After(a) {
		a, b = b, a
	}
	return a.Sub(b)
}
