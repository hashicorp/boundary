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
	"golang.org/x/crypto/ssh/testdata"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestSshPrivateKeyCredential_New(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kkms := kms.TestKms(t, conn, wrapper)
	rw := db.New(conn)

	privKey := []byte(TestSshPrivateKeyPem)
	ePrivKey := testdata.PEMEncryptedKeys[0].PEMBytes
	ePrivKeyPass := testdata.PEMEncryptedKeys[0].EncryptionKey

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cs := TestCredentialStore(t, conn, wrapper, prj.PublicId)

	type args struct {
		username      string
		sshPrivateKey credential.PrivateKey
		storeId       string
		options       []Option
	}

	tests := []struct {
		name           string
		args           args
		want           *SshPrivateKeyCredential
		wantCreateErr  bool
		wantEncryptErr bool
		wantAllocError bool
	}{
		{
			name: "missing-private-key",
			args: args{
				username: "test-user",
				storeId:  cs.PublicId,
			},
			want:           allocSshPrivateKeyCredential(),
			wantEncryptErr: true,
		},
		{
			name: "missing-username",
			args: args{
				sshPrivateKey: privKey,
				storeId:       cs.PublicId,
			},
			want:          allocSshPrivateKeyCredential(),
			wantCreateErr: true,
		},
		{
			name: "missing-store-id",
			args: args{
				username:      "test-user",
				sshPrivateKey: privKey,
			},
			want:          allocSshPrivateKeyCredential(),
			wantCreateErr: true,
		},
		{
			name: "bad-private-key",
			args: args{
				username:      "test-user",
				sshPrivateKey: []byte("foobar"),
				storeId:       cs.PublicId,
			},
			want:           allocSshPrivateKeyCredential(),
			wantAllocError: true,
		},
		{
			name: "valid-no-options",
			args: args{
				username:      "test-user",
				sshPrivateKey: privKey,
				storeId:       cs.PublicId,
			},
			want: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Username:   "test-user",
					PrivateKey: privKey,
					StoreId:    cs.PublicId,
				},
			},
		},
		{
			name: "valid-with-name",
			args: args{
				username:      "test-user",
				sshPrivateKey: privKey,
				storeId:       cs.PublicId,
				options:       []Option{WithName("my-credential")},
			},
			want: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Username:   "test-user",
					PrivateKey: privKey,
					StoreId:    cs.PublicId,
					Name:       "my-credential",
				},
			},
		},
		{
			name: "valid-with-description",
			args: args{
				username:      "test-user",
				sshPrivateKey: privKey,
				storeId:       cs.PublicId,
				options:       []Option{WithDescription("my-credential-description")},
			},
			want: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Username:    "test-user",
					PrivateKey:  privKey,
					StoreId:     cs.PublicId,
					Description: "my-credential-description",
				},
			},
		},
		{
			name: "invalid-passphrase",
			args: args{
				username:      "test-user",
				sshPrivateKey: privKey,
				storeId:       cs.PublicId,
				options:       []Option{WithPrivateKeyPassphrase([]byte(ePrivKeyPass))},
			},
			wantAllocError: true,
		},
		{
			name: "valid-with-passphrase",
			args: args{
				username:      "test-user",
				sshPrivateKey: ePrivKey,
				storeId:       cs.PublicId,
				options:       []Option{WithPrivateKeyPassphrase([]byte(ePrivKeyPass))},
			},
			want: &SshPrivateKeyCredential{
				SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
					Username:             "test-user",
					PrivateKey:           ePrivKey,
					StoreId:              cs.PublicId,
					PrivateKeyPassphrase: []byte(ePrivKeyPass),
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			got, err := NewSshPrivateKeyCredential(ctx, tt.args.storeId, tt.args.username, tt.args.sshPrivateKey, tt.args.options...)
			if tt.wantAllocError {
				assert.Error(err)
				return
			}
			require.NoError(err)
			require.NotNil(got)
			assert.Emptyf(got.PublicId, "PublicId set")

			id, err := credential.NewSshPrivateKeyCredentialId(ctx)
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

			got2 := allocSshPrivateKeyCredential()
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
			got2.PrivateKeyEncrypted = nil
			got2.PrivateKeyPassphraseEncrypted = nil

			// encrypt also calculates the hmac, validate it is correct
			hm, err := crypto.HmacSha256(ctx, got.PrivateKey, databaseWrapper, []byte(got.StoreId), nil)
			require.NoError(err)
			tt.want.PrivateKeyHmac = []byte(hm)

			if len(got.PrivateKeyPassphrase) > 0 {
				// encrypt also calculates the hmac, validate it is correct
				hm, err = crypto.HmacSha256(ctx, got.PrivateKeyPassphrase, databaseWrapper, []byte(got.StoreId), nil)
				require.NoError(err)
				tt.want.PrivateKeyPassphraseHmac = []byte(hm)
			}

			assert.Empty(cmp.Diff(tt.want, got2.clone(), protocmp.Transform()))
		})
	}
}
