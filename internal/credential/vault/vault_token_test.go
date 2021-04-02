package vault

import (
	"context"
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
)

func TestToken_New(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)

	kkms := kms.TestKms(t, conn, wrapper)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cs := TestCredentialStores(t, conn, wrapper, prj.PublicId, 1)[0]

	type args struct {
		storeId    string
		token      []byte
		expiration time.Duration
	}

	sum := func(t []byte) []byte {
		sm := sha256.Sum256(t)
		return sm[:]
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
				token:      []byte("token"),
				expiration: 5 * time.Minute,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "missing-token",
			args: args{
				storeId:    cs.PublicId,
				expiration: 5 * time.Minute,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "missing-expiration",
			args: args{
				storeId: cs.PublicId,
				token:   []byte("token"),
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				storeId:    cs.PublicId,
				token:      []byte("token"),
				expiration: 5 * time.Minute,
			},
			want: &Token{
				Token: &store.Token{
					StoreId:     cs.PublicId,
					Token:       []byte("token"),
					TokenSha256: sum([]byte("token")),
					Status:      string(StatusCurrent),
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

			got, err := newToken(tt.args.storeId, tt.args.token, tt.args.expiration)
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

			rows, err2 := rw.Exec(ctx, insertTokenQuery, got.valuesForInsert())
			assert.Equal(1, rows)
			assert.NoError(err2)

			insertedToken := allocToken()
			require.NoError(rw.LookupWhere(ctx, &insertedToken, "token_sha256 = ?", got.TokenSha256))
			require.NoError(insertedToken.decrypt(ctx, databaseWrapper))

			gotExpirationDuration := subtract(t, insertedToken.LastRenewalTime, insertedToken.ExpirationTime)
			assert.Equal(tt.want.expiration, gotExpirationDuration)

			// TODO(mgaffney) 04/2021: Move to repository tests
			/*
				got.CreateTime = insertedToken.CreateTime
				got.UpdateTime = insertedToken.UpdateTime
				got.LastRenewalTime = insertedToken.LastRenewalTime
				got.ExpirationTime = insertedToken.ExpirationTime

				assert.Empty(cmp.Diff(tt.want, got, protocmp.Transform()))
			*/
		})
	}
}

func (t *Token) valuesForInsert() []interface{} {
	exp := int(t.expiration.Round(time.Second).Seconds())
	return []interface{}{
		t.TokenSha256,
		t.CtToken,
		t.StoreId,
		t.KeyId,
		t.Status,
		"now()",
		exp,
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
