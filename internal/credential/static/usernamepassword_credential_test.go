// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

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

func TestUsernamePasswordCredential_New(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kkms := kms.TestKms(t, conn, wrapper)
	rw := db.New(conn)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cs := TestCredentialStore(t, conn, wrapper, prj.PublicId)

	type args struct {
		username string
		password credential.Password
		storeId  string
		options  []Option
	}

	tests := []struct {
		name           string
		args           args
		want           *UsernamePasswordCredential
		wantCreateErr  bool
		wantEncryptErr bool
	}{
		{
			name: "missing-password",
			args: args{
				username: "test-user",
				storeId:  cs.PublicId,
			},
			want:           allocUsernamePasswordCredential(),
			wantEncryptErr: true,
		},
		{
			name: "missing-username",
			args: args{
				password: "test-pass",
				storeId:  cs.PublicId,
			},
			want:          allocUsernamePasswordCredential(),
			wantCreateErr: true,
		},
		{
			name: "missing-store-id",
			args: args{
				username: "test-user",
				password: "test-pass",
			},
			want:          allocUsernamePasswordCredential(),
			wantCreateErr: true,
		},
		{
			name: "valid-no-options",
			args: args{
				username: "test-user",
				password: "test-pass",
				storeId:  cs.PublicId,
			},
			want: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Username: "test-user",
					Password: []byte("test-pass"),
					StoreId:  cs.PublicId,
				},
			},
		},
		{
			name: "valid-with-name",
			args: args{
				username: "test-user",
				password: "test-pass",
				storeId:  cs.PublicId,
				options:  []Option{WithName("my-credential")},
			},
			want: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Username: "test-user",
					Password: []byte("test-pass"),
					StoreId:  cs.PublicId,
					Name:     "my-credential",
				},
			},
		},
		{
			name: "valid-with-description",
			args: args{
				username: "test-user",
				password: "test-pass",
				storeId:  cs.PublicId,
				options:  []Option{WithDescription("my-credential-description")},
			},
			want: &UsernamePasswordCredential{
				UsernamePasswordCredential: &store.UsernamePasswordCredential{
					Username:    "test-user",
					Password:    []byte("test-pass"),
					StoreId:     cs.PublicId,
					Description: "my-credential-description",
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			got, err := NewUsernamePasswordCredential(tt.args.storeId, tt.args.username, tt.args.password, tt.args.options...)
			require.NoError(err)
			require.NotNil(got)
			assert.Emptyf(got.PublicId, "PublicId set")

			id, err := credential.NewUsernamePasswordCredentialId(ctx)
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

			got2 := allocUsernamePasswordCredential()
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
			got2.CtPassword = nil

			// encrypt also calculates the hmac, validate it is correct
			hm, err := crypto.HmacSha256(ctx, got.Password, databaseWrapper, []byte(got.StoreId), nil, crypto.WithEd25519())
			require.NoError(err)
			tt.want.PasswordHmac = []byte(hm)

			assert.Empty(cmp.Diff(tt.want, got2.clone(), protocmp.Transform()))
		})
	}
}
