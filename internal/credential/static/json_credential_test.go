// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package static

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/static/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/libs/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestJsonCredential_New(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kkms := kms.TestKms(t, conn, wrapper)
	rw := db.New(conn)

	obj, objBytes := TestJsonObject(t)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cs := TestCredentialStore(t, conn, wrapper, prj.PublicId)

	type args struct {
		object  credential.JsonObject
		storeId string
		options []Option
	}

	tests := []struct {
		name           string
		args           args
		want           *JsonCredential
		wantCreateErr  bool
		wantEncryptErr bool
		wantAllocError bool
	}{
		{
			name: "missing-store-id",
			args: args{
				object: obj,
			},
			want:          allocJsonCredential(),
			wantCreateErr: true,
		},
		{
			name: "valid-no-options",
			args: args{
				object:  obj,
				storeId: cs.PublicId,
			},
			want: &JsonCredential{
				JsonCredential: &store.JsonCredential{
					Object:  objBytes,
					StoreId: cs.PublicId,
				},
			},
		},
		{
			name: "valid-with-name",
			args: args{
				object:  obj,
				storeId: cs.PublicId,
				options: []Option{WithName("json-credential")},
			},
			want: &JsonCredential{
				JsonCredential: &store.JsonCredential{
					Object:  objBytes,
					StoreId: cs.PublicId,
					Name:    "json-credential",
				},
			},
		},
		{
			name: "valid-with-description",
			args: args{
				object:  obj,
				storeId: cs.PublicId,
				options: []Option{WithDescription("key-value secrets")},
			},
			want: &JsonCredential{
				JsonCredential: &store.JsonCredential{
					Object:      objBytes,
					StoreId:     cs.PublicId,
					Description: "key-value secrets",
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()

			got, err := NewJsonCredential(ctx, tt.args.storeId, tt.args.object, tt.args.options...)
			if tt.wantAllocError {
				assert.Error(err)
				return
			}
			require.NoError(err)
			require.NotNil(got)
			assert.Emptyf(got.PublicId, "PublicId set")

			id, err := credential.NewJsonCredentialId(ctx)
			require.NoError(err)

			tt.want.PublicId = id
			got.PublicId = id

			databaseWrapper, err := kkms.GetWrapper(context.Background(), prj.PublicId, kms.KeyPurposeDatabase)
			require.NoError(err)

			err = got.encrypt(ctx, databaseWrapper)
			if tt.wantEncryptErr {
				require.Error(err)
				return
			}
			assert.NoError(err)

			err = rw.Create(context.Background(), got)
			if tt.wantCreateErr {
				require.Error(err)
				return
			}
			assert.NoError(err)

			got2 := allocJsonCredential()
			got2.PublicId = id
			assert.Equal(id, got2.GetPublicId())
			require.NoError(rw.LookupById(ctx, got2))

			err = got2.decrypt(ctx, databaseWrapper)
			require.NoError(err)

			// Timestamps and version are automatically set
			tt.want.CreateTime = got2.CreateTime
			tt.want.UpdateTime = got2.UpdateTime
			tt.want.Version = got2.Version

			// KeyId is allocated via kms no need to validate in this test
			tt.want.KeyId = got2.KeyId
			got2.ObjectEncrypted = nil

			// encrypt also calculates the hmac, validate it is correct
			hm, err := crypto.HmacSha256(ctx, got.Object, databaseWrapper, []byte(got.StoreId), nil)
			require.NoError(err)
			tt.want.ObjectHmac = []byte(hm)

			assert.Empty(cmp.Diff(tt.want, got2.clone(), protocmp.Transform()))
		})
	}
}
