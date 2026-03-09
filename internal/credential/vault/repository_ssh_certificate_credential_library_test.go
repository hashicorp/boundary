// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/db"
	dbassert "github.com/hashicorp/boundary/internal/db/assert"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_CreateSSHCertificateCredentialLibrary(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cs := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]

	tests := []struct {
		name    string
		in      *SSHCertificateCredentialLibrary
		opts    []Option
		want    *SSHCertificateCredentialLibrary
		wantErr errors.Code
	}{
		{
			name:    "nil-SSHCertificateCredentialLibrary",
			wantErr: errors.InvalidParameter,
		},
		{
			name:    "nil-embedded-SSHCertificateCredentialLibrary",
			in:      &SSHCertificateCredentialLibrary{},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "invalid-no-store-id",
			in: func() *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary("", "/ssh/sign/foo", "name")
				return s
			}(),
			wantErr: errors.InvalidParameter,
		},
		{
			name: "invalid-public-id-set",
			in: func() *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					cs.GetPublicId(),
					"/ssh/sign/foo",
					"name",
				)
				s.PublicId = "abcd_OOOOOOOOOO"
				return s
			}(),
			wantErr: errors.InvalidParameter,
		},
		{
			name: "invalid-no-vault-path",
			in: func() *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					cs.GetPublicId(),
					"",
					"name",
				)
				return s
			}(),
			wantErr: errors.InvalidParameter,
		},
		{
			name: "invalid-vault-path-invalid-endpoint",
			in: func() *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					cs.GetPublicId(),
					"/ssh/not-sign/foo",
					"name",
				)
				return s
			}(),
			wantErr: errors.CheckConstraint,
		},
		{
			name: "invalid-no-username",
			in: func() *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					cs.GetPublicId(),
					"/ssh/sign/foo",
					"",
				)
				return s
			}(),
			wantErr: errors.InvalidParameter,
		},
		{
			name: "valid-no-options",
			in: func() *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					cs.GetPublicId(),
					"/ssh/sign/foo",
					"name",
				)
				return s
			}(),
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					StoreId:   cs.GetPublicId(),
					VaultPath: "/ssh/sign/foo",
					Username:  "name",
					KeyType:   KeyTypeEd25519,
					KeyBits:   0,
				},
			},
		},
		{
			name: "valid-with-name",
			in: func() *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					cs.GetPublicId(),
					"/ssh/sign/foo",
					"name",
					WithName("test-name-repo"),
				)
				return s
			}(),
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					StoreId:   cs.GetPublicId(),
					Name:      "test-name-repo",
					VaultPath: "/ssh/sign/foo",
					Username:  "name",
					KeyType:   KeyTypeEd25519,
					KeyBits:   0,
				},
			},
		},
		{
			name: "valid-with-description",
			in: func() *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					cs.GetPublicId(),
					"/ssh/sign/foo",
					"name",
					WithDescription("test-description-repo"),
				)
				return s
			}(),
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					StoreId:     cs.GetPublicId(),
					Description: "test-description-repo",
					VaultPath:   "/ssh/sign/foo",
					Username:    "name",
					KeyType:     KeyTypeEd25519,
					KeyBits:     0,
				},
			},
		},
		{
			name: "valid-key-type-ed25519",
			in: func() *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					cs.GetPublicId(),
					"/ssh/sign/foo",
					"name",
					WithKeyType(KeyTypeEd25519),
					WithKeyBits(KeyBitsDefault),
				)
				return s
			}(),
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					StoreId:   cs.GetPublicId(),
					VaultPath: "/ssh/sign/foo",
					Username:  "name",
					KeyType:   KeyTypeEd25519,
					KeyBits:   KeyBitsDefault,
				},
			},
		},
		{
			name: "valid-key-type-ecdsa-0",
			in: func() *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					cs.GetPublicId(),
					"/ssh/sign/foo",
					"name",
					WithKeyType(KeyTypeEcdsa),
					WithKeyBits(KeyBitsDefault),
				)
				return s
			}(),
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					StoreId:   cs.GetPublicId(),
					VaultPath: "/ssh/sign/foo",
					Username:  "name",
					KeyType:   KeyTypeEcdsa,
					KeyBits:   KeyBitsEcdsa256,
				},
			},
		},
		{
			name: "valid-key-type-ecdsa-256",
			in: func() *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					cs.GetPublicId(),
					"/ssh/sign/foo",
					"name",
					WithKeyType(KeyTypeEcdsa),
					WithKeyBits(KeyBitsEcdsa256),
				)
				return s
			}(),
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					StoreId:   cs.GetPublicId(),
					VaultPath: "/ssh/sign/foo",
					Username:  "name",
					KeyType:   KeyTypeEcdsa,
					KeyBits:   KeyBitsEcdsa256,
				},
			},
		},
		{
			name: "valid-key-type-ecdsa-384",
			in: func() *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					cs.GetPublicId(),
					"/ssh/sign/foo",
					"name",
					WithKeyType(KeyTypeEcdsa),
					WithKeyBits(KeyBitsEcdsa384),
				)
				return s
			}(),
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					StoreId:   cs.GetPublicId(),
					VaultPath: "/ssh/sign/foo",
					Username:  "name",
					KeyType:   KeyTypeEcdsa,
					KeyBits:   KeyBitsEcdsa384,
				},
			},
		},
		{
			name: "valid-key-type-ecdsa-521",
			in: func() *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					cs.GetPublicId(),
					"/ssh/sign/foo",
					"name",
					WithKeyType(KeyTypeEcdsa),
					WithKeyBits(KeyBitsEcdsa521),
				)
				return s
			}(),
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					StoreId:   cs.GetPublicId(),
					VaultPath: "/ssh/sign/foo",
					Username:  "name",
					KeyType:   KeyTypeEcdsa,
					KeyBits:   KeyBitsEcdsa521,
				},
			},
		},
		{
			name: "valid-key-type-rsa-0",
			in: func() *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					cs.GetPublicId(),
					"/ssh/sign/foo",
					"name",
					WithKeyType(KeyTypeRsa),
					WithKeyBits(KeyBitsDefault),
				)
				return s
			}(),
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					StoreId:   cs.GetPublicId(),
					VaultPath: "/ssh/sign/foo",
					Username:  "name",
					KeyType:   KeyTypeRsa,
					KeyBits:   KeyBitsRsa2048,
				},
			},
		},
		{
			name: "valid-key-type-rsa-2048",
			in: func() *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					cs.GetPublicId(),
					"/ssh/sign/foo",
					"name",
					WithKeyType(KeyTypeRsa),
					WithKeyBits(KeyBitsRsa2048),
				)
				return s
			}(),
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					StoreId:   cs.GetPublicId(),
					VaultPath: "/ssh/sign/foo",
					Username:  "name",
					KeyType:   KeyTypeRsa,
					KeyBits:   KeyBitsRsa2048,
				},
			},
		},
		{
			name: "valid-key-type-rsa-3072",
			in: func() *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					cs.GetPublicId(),
					"/ssh/sign/foo",
					"name",
					WithKeyType(KeyTypeRsa),
					WithKeyBits(KeyBitsRsa3072),
				)
				return s
			}(),
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					StoreId:   cs.GetPublicId(),
					VaultPath: "/ssh/sign/foo",
					Username:  "name",
					KeyType:   KeyTypeRsa,
					KeyBits:   KeyBitsRsa3072,
				},
			},
		},
		{
			name: "valid-key-type-rsa-4096",
			in: func() *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					cs.GetPublicId(),
					"/ssh/sign/foo",
					"name",
					WithKeyType(KeyTypeRsa),
					WithKeyBits(KeyBitsRsa4096),
				)
				return s
			}(),
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					StoreId:   cs.GetPublicId(),
					VaultPath: "/ssh/sign/foo",
					Username:  "name",
					KeyType:   KeyTypeRsa,
					KeyBits:   KeyBitsRsa4096,
				},
			},
		},
		{
			name: "invalid-key-type-key-bits-ecdsa-2048",
			in: func() *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					cs.GetPublicId(),
					"/ssh/sign/foo",
					"name",
					WithKeyType(KeyTypeEcdsa),
					WithKeyBits(KeyBitsRsa2048),
				)
				return s
			}(),
			wantErr: errors.NotSpecificIntegrity,
		},
		{
			name: "invalid-key-type-key-bits-ecdsa-3072",
			in: func() *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					cs.GetPublicId(),
					"/ssh/sign/foo",
					"name",
					WithKeyType(KeyTypeEcdsa),
					WithKeyBits(KeyBitsRsa3072),
				)
				return s
			}(),
			wantErr: errors.NotSpecificIntegrity,
		},
		{
			name: "invalid-key-type-key-bits-ecdsa-4096",
			in: func() *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					cs.GetPublicId(),
					"/ssh/sign/foo",
					"name",
					WithKeyType(KeyTypeEcdsa),
					WithKeyBits(KeyBitsRsa4096),
				)
				return s
			}(),
			wantErr: errors.NotSpecificIntegrity,
		},
		{
			name: "invalid-key-type-key-bits-rsa-256",
			in: func() *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					cs.GetPublicId(),
					"/ssh/sign/foo",
					"name",
					WithKeyType(KeyTypeRsa),
					WithKeyBits(KeyBitsEcdsa256),
				)
				return s
			}(),
			wantErr: errors.NotSpecificIntegrity,
		},
		{
			name: "invalid-key-type-key-bits-rsa-384",
			in: func() *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					cs.GetPublicId(),
					"/ssh/sign/foo",
					"name",
					WithKeyType(KeyTypeRsa),
					WithKeyBits(KeyBitsEcdsa384),
				)
				return s
			}(),
			wantErr: errors.NotSpecificIntegrity,
		},
		{
			name: "invalid-key-type-key-bits-rsa-521",
			in: func() *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					cs.GetPublicId(),
					"/ssh/sign/foo",
					"name",
					WithKeyType(KeyTypeRsa),
					WithKeyBits(KeyBitsEcdsa521),
				)
				return s
			}(),
			wantErr: errors.NotSpecificIntegrity,
		},
		{
			name: "invalid-key-type-key-bits-ed25519-256",
			in: func() *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					cs.GetPublicId(),
					"/ssh/sign/foo",
					"name",
					WithKeyType(KeyTypeEd25519),
					WithKeyBits(KeyBitsEcdsa256),
				)
				return s
			}(),
			wantErr: errors.NotSpecificIntegrity,
		},
		{
			name: "invalid-key-type-key-bits-ed25519-384",
			in: func() *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					cs.GetPublicId(),
					"/ssh/sign/foo",
					"name",
					WithKeyType(KeyTypeEd25519),
					WithKeyBits(KeyBitsEcdsa384),
				)
				return s
			}(),
			wantErr: errors.NotSpecificIntegrity,
		},
		{
			name: "invalid-key-type-key-bits-ed25519-521",
			in: func() *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					cs.GetPublicId(),
					"/ssh/sign/foo",
					"name",
					WithKeyType(KeyTypeEd25519),
					WithKeyBits(KeyBitsEcdsa521),
				)
				return s
			}(),
			wantErr: errors.NotSpecificIntegrity,
		},
		{
			name: "invalid-key-type-key-bits-ed25519-2048",
			in: func() *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					cs.GetPublicId(),
					"/ssh/sign/foo",
					"name",
					WithKeyType(KeyTypeEd25519),
					WithKeyBits(KeyBitsRsa2048),
				)
				return s
			}(),
			wantErr: errors.NotSpecificIntegrity,
		},
		{
			name: "invalid-key-type-key-bits-ed25519-3072",
			in: func() *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					cs.GetPublicId(),
					"/ssh/sign/foo",
					"name",
					WithKeyType(KeyTypeEd25519),
					WithKeyBits(KeyBitsRsa3072),
				)
				return s
			}(),
			wantErr: errors.NotSpecificIntegrity,
		},
		{
			name: "invalid-key-type-key-bits-ed25519-4096",
			in: func() *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					cs.GetPublicId(),
					"/ssh/sign/foo",
					"name",
					WithKeyType(KeyTypeEd25519),
					WithKeyBits(KeyBitsRsa4096),
				)
				return s
			}(),
			wantErr: errors.NotSpecificIntegrity,
		},
		{
			name: "valid-critical-options",
			in: func() *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					cs.GetPublicId(),
					"/ssh/sign/foo",
					"name",
					WithCriticalOptions(`{"force-command": "/bin/foo"}`),
				)
				return s
			}(),
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					StoreId:         cs.GetPublicId(),
					VaultPath:       "/ssh/sign/foo",
					Username:        "name",
					KeyType:         KeyTypeEd25519,
					KeyBits:         0,
					CriticalOptions: `{"force-command": "/bin/foo"}`,
				},
			},
		},
		{
			name: "valid-extensions",
			in: func() *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					cs.GetPublicId(),
					"/ssh/sign/foo",
					"name",
					WithExtensions(`{"permit-X11-forwarding": "", "permit-pty": ""}`),
				)
				return s
			}(),
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					StoreId:    cs.GetPublicId(),
					VaultPath:  "/ssh/sign/foo",
					Username:   "name",
					KeyType:    KeyTypeEd25519,
					KeyBits:    0,
					Extensions: `{"permit-X11-forwarding": "", "permit-pty": ""}`,
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			kms := kms.TestKms(t, conn, wrapper)
			sche := scheduler.TestScheduler(t, conn, wrapper)
			repo, err := NewRepository(ctx, rw, rw, kms, sche)
			require.NoError(err)
			require.NotNil(repo)
			got, err := repo.CreateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), tt.in, tt.opts...)
			if tt.wantErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			assert.Empty(tt.in.PublicId)
			require.NotNil(got)
			assertPublicId(t, globals.VaultSshCertificateCredentialLibraryPrefix, got.GetPublicId())
			assert.NotSame(tt.in, got)
			assert.Equal(tt.want.Name, got.Name)
			assert.Equal(tt.want.Description, got.Description)
			assert.Equal(tt.want.KeyType, got.KeyType)
			assert.Equal(tt.want.KeyBits, got.KeyBits)
			assert.Equal(tt.want.KeyId, got.KeyId)
			assert.Equal(tt.want.Ttl, got.Ttl)
			assert.Equal(tt.want.CriticalOptions, got.CriticalOptions)
			assert.Equal(tt.want.Extensions, got.Extensions)
			assert.Equal(got.CredentialType(), globals.SshCertificateCredentialType)
			assert.Equal(got.CreateTime, got.UpdateTime)

			assert.NoError(db.TestVerifyOplog(t, rw, got.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))
		})
	}

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		sche := scheduler.TestScheduler(t, conn, wrapper)
		repo, err := NewRepository(ctx, rw, rw, kms, sche)
		require.NoError(err)
		require.NotNil(repo)
		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		cs := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]
		in := &SSHCertificateCredentialLibrary{
			SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
				StoreId:   cs.GetPublicId(),
				KeyType:   KeyTypeEd25519,
				VaultPath: "/ssh/sign/foo",
				Name:      "test-name-repo",
				Username:  "name",
			},
		}

		got, err := repo.CreateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), in)
		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, globals.VaultSshCertificateCredentialLibraryPrefix, got.GetPublicId())
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		got2, err := repo.CreateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), in)
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "want err: %q got: %q", errors.NotUnique, err)
		assert.Nil(got2)
	})

	t.Run("valid-duplicate-names-diff-stores", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		sche := scheduler.TestScheduler(t, conn, wrapper)
		repo, err := NewRepository(ctx, rw, rw, kms, sche)
		require.NoError(err)
		require.NotNil(repo)

		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		css := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 2)

		csA, csB := css[0], css[1]

		in := &SSHCertificateCredentialLibrary{
			SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
				KeyType:   KeyTypeEd25519,
				VaultPath: "/ssh/sign/foo",
				Name:      "test-name-repo",
				Username:  "name",
			},
		}
		in2 := in.clone()

		in.StoreId = csA.GetPublicId()
		got, err := repo.CreateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), in)
		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, globals.VaultSshCertificateCredentialLibraryPrefix, got.GetPublicId())
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		in2.StoreId = csB.GetPublicId()
		got2, err := repo.CreateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), in2)
		require.NoError(err)
		require.NotNil(got2)
		assertPublicId(t, globals.VaultSshCertificateCredentialLibraryPrefix, got2.GetPublicId())
		assert.NotSame(in2, got2)
		assert.Equal(in2.Name, got2.Name)
		assert.Equal(in2.Description, got2.Description)
		assert.Equal(got2.CreateTime, got2.UpdateTime)
	})
}

func TestRepository_LookupSSHCertificateCredentialLibrary(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	{
		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		css := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 2)

		cs := css[0]
		csWithExpiredToken := css[1]
		rows, err := rw.Exec(context.Background(),
			"update credential_vault_token set status = ? where token_hmac = ?",
			[]any{ExpiredToken, csWithExpiredToken.Token().TokenHmac})
		require.NoError(t, err)
		require.Equal(t, 1, rows)

		tests := []struct {
			name string
			in   *SSHCertificateCredentialLibrary
		}{
			{
				name: "valid-no-options",
				in: &SSHCertificateCredentialLibrary{
					SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
						StoreId:   cs.GetPublicId(),
						VaultPath: "/ssh/sign/foo",
						Username:  "name",
					},
				},
			},

			{
				name: "valid-with-expired-cred-store-token",
				in: &SSHCertificateCredentialLibrary{
					SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
						StoreId:   csWithExpiredToken.GetPublicId(),
						VaultPath: "/ssh/sign/foo",
						Username:  "name",
					},
				},
			},
			{
				name: "valid-ssh-certificate-credential-type",
				in: &SSHCertificateCredentialLibrary{
					SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
						StoreId:        cs.GetPublicId(),
						VaultPath:      "/ssh/sign/foo",
						Username:       "name",
						CredentialType: string(globals.SshCertificateCredentialType),
					},
				},
			},
		}

		for _, tt := range tests {
			tt := tt
			t.Run(tt.name, func(t *testing.T) {
				// setup
				assert, require := assert.New(t), require.New(t)
				ctx := context.Background()
				kms := kms.TestKms(t, conn, wrapper)
				sche := scheduler.TestScheduler(t, conn, wrapper)
				repo, err := NewRepository(ctx, rw, rw, kms, sche)
				assert.NoError(err)
				require.NotNil(repo)
				orig, err := repo.CreateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), tt.in)
				assert.NoError(err)
				require.NotEmpty(orig)
				// test
				got, err := repo.LookupSSHCertificateCredentialLibrary(ctx, orig.GetPublicId())
				assert.NoError(err)
				require.NotEmpty(got)
				assert.Equal(orig.Name, got.Name)
				assert.Equal(orig.Description, got.Description)
				assert.Equal(orig.CredentialType(), got.CredentialType())
			})
		}
	}

	t.Run("empty-public-id", func(t *testing.T) {
		// setup
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		sche := scheduler.TestScheduler(t, conn, wrapper)
		repo, err := NewRepository(ctx, rw, rw, kms, sche)
		assert.NoError(err)
		require.NotNil(repo)
		// test
		got, err := repo.LookupCredentialLibrary(ctx, "")
		wantErr := errors.InvalidParameter
		assert.Truef(errors.Match(errors.T(wantErr), err), "want err: %q got: %q", wantErr, err)
		assert.Nil(got)
	})

	t.Run("not-found", func(t *testing.T) {
		// setup
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		sche := scheduler.TestScheduler(t, conn, wrapper)
		repo, err := NewRepository(ctx, rw, rw, kms, sche)
		assert.NoError(err)
		require.NotNil(repo)
		badId, err := newSSHCertificateCredentialLibraryId(ctx)
		assert.NoError(err)
		require.NotNil(badId)
		// test
		got, err := repo.LookupCredentialLibrary(ctx, badId)
		assert.NoError(err)
		assert.Empty(got)
	})
}

func TestRepository_UpdateSSHCertificateCredentialLibrary(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	changeVaultPath := func(p string) func(*SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
		return func(l *SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
			l.VaultPath = p
			return l
		}
	}

	changeName := func(n string) func(*SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
		return func(l *SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
			l.Name = n
			return l
		}
	}

	changeDescription := func(d string) func(*SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
		return func(l *SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
			l.Description = d
			return l
		}
	}

	changeUsername := func(s string) func(*SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
		return func(l *SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
			l.Username = s
			return l
		}
	}

	changeKeyType := func(s string) func(*SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
		return func(l *SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
			l.KeyType = s
			return l
		}
	}

	changeKeyBits := func(b uint32) func(*SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
		return func(l *SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
			l.KeyBits = b
			return l
		}
	}

	changeTtl := func(s string) func(*SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
		return func(l *SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
			l.Ttl = s
			return l
		}
	}

	changeKeyId := func(s string) func(*SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
		return func(l *SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
			l.KeyId = s
			return l
		}
	}

	changeCriticalOptions := func(s string) func(*SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
		return func(l *SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
			l.CriticalOptions = s
			return l
		}
	}

	changeExtensions := func(s string) func(*SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
		return func(l *SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
			l.Extensions = s
			return l
		}
	}

	makeNil := func() func(*SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
		return func(l *SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
			return nil
		}
	}

	makeEmbeddedNil := func() func(*SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
		return func(l *SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
			return &SSHCertificateCredentialLibrary{}
		}
	}

	deletePublicId := func() func(*SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
		return func(l *SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
			l.PublicId = ""
			return l
		}
	}

	nonExistentPublicId := func() func(*SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
		return func(l *SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
			l.PublicId = "abcd_OOOOOOOOOO"
			return l
		}
	}

	combine := func(fns ...func(l *SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary) func(*SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
		return func(l *SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary {
			for _, fn := range fns {
				l = fn(l)
			}
			return l
		}
	}

	tests := []struct {
		name      string
		origFn    func(string) *SSHCertificateCredentialLibrary
		chgFn     func(*SSHCertificateCredentialLibrary) *SSHCertificateCredentialLibrary
		masks     []string
		want      *SSHCertificateCredentialLibrary
		wantCount int
		wantErr   errors.Code
	}{
		{
			name: "nil-credential-library",
			origFn: func(csId string) *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					csId,
					"/ssh/sign/foo",
					"name",
				)
				return s
			},
			chgFn:   makeNil(),
			masks:   []string{nameField, descriptionField},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "nil-embedded-credential-library",
			origFn: func(csId string) *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					csId,
					"/ssh/sign/foo",
					"name",
				)
				return s
			},
			chgFn:   makeEmbeddedNil(),
			masks:   []string{nameField, descriptionField},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "no-public-id",
			origFn: func(csId string) *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					csId,
					"/ssh/sign/foo",
					"name",
				)
				return s
			},
			chgFn:   deletePublicId(),
			masks:   []string{nameField, descriptionField},
			wantErr: errors.InvalidPublicId,
		},
		{
			name: "updating-non-existent-credential-library",
			origFn: func(csId string) *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					csId,
					"/ssh/sign/foo",
					"name",
					WithName("test-name-repo"),
				)
				return s
			},
			chgFn:   combine(nonExistentPublicId(), changeName("test-update-name-repo")),
			masks:   []string{nameField},
			wantErr: errors.RecordNotFound,
		},
		{
			name: "empty-field-mask",
			origFn: func(csId string) *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					csId,
					"/ssh/sign/foo",
					"name",
					WithName("test-name-repo"),
				)
				return s
			},
			chgFn:   changeName("test-update-name-repo"),
			wantErr: errors.EmptyFieldMask,
		},
		{
			name: "read-only-fields-in-field-mask",
			origFn: func(csId string) *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					csId,
					"/ssh/sign/foo",
					"name",
					WithName("test-name-repo"),
				)
				return s
			},
			chgFn:   changeName("test-update-name-repo"),
			masks:   []string{"PublicId", "CreateTime", "UpdateTime", "StoreId"},
			wantErr: errors.InvalidFieldMask,
		},
		{
			name: "unknown-field-in-field-mask",
			origFn: func(csId string) *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					csId,
					"/ssh/sign/foo",
					"name",
					WithName("test-name-repo"),
				)
				return s
			},
			chgFn:   changeName("test-update-name-repo"),
			masks:   []string{"Bilbo"},
			wantErr: errors.InvalidFieldMask,
		},
		{
			name: "change-name",
			origFn: func(csId string) *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					csId,
					"/ssh/sign/foo",
					"name",
					WithName("test-name-repo"),
				)
				return s
			},
			chgFn: changeName("test-update-name-repo"),
			masks: []string{nameField},
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					VaultPath: "/ssh/sign/foo",
					Username:  "name",
					Name:      "test-update-name-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-description",
			origFn: func(csId string) *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					csId,
					"/ssh/sign/foo",
					"name",
					WithDescription("test-description-repo"),
				)
				return s
			},
			chgFn: changeDescription("test-update-description-repo"),
			masks: []string{descriptionField},
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					VaultPath:   "/ssh/sign/foo",
					Username:    "name",
					Description: "test-update-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-name-and-description",
			origFn: func(csId string) *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					csId,
					"/ssh/sign/foo",
					"name",
					WithName("test-name-repo"),
					WithDescription("test-description-repo"),
				)
				return s
			},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("test-update-name-repo")),
			masks: []string{nameField, descriptionField},
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					VaultPath:   "/ssh/sign/foo",
					Username:    "name",
					Name:        "test-update-name-repo",
					Description: "test-update-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-username",
			origFn: func(csId string) *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					csId,
					"/ssh/sign/foo",
					"name",
				)
				return s
			},
			chgFn: changeUsername("update-name"),
			masks: []string{usernameField},
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					VaultPath: "/ssh/sign/foo",
					Username:  "update-name",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-keytype",
			origFn: func(csId string) *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					csId,
					"/ssh/sign/foo",
					"name",
					WithKeyType(KeyTypeEd25519),
				)
				return s
			},
			chgFn: combine(changeKeyType(KeyTypeEcdsa), changeKeyBits(KeyBitsDefault)),
			masks: []string{keyTypeField, keyBitsField},
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					KeyType:   KeyTypeEcdsa,
					KeyBits:   KeyBitsEcdsa256,
					VaultPath: "/ssh/sign/foo",
					Username:  "name",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-keybits",
			origFn: func(csId string) *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					csId,
					"/ssh/sign/foo",
					"name",
					WithKeyType(KeyTypeEcdsa),
					WithKeyBits(KeyBitsEcdsa256),
				)
				return s
			},
			chgFn: changeKeyBits(KeyBitsEcdsa384),
			masks: []string{keyBitsField},
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					KeyType:   KeyTypeEcdsa,
					KeyBits:   KeyBitsEcdsa384,
					VaultPath: "/ssh/sign/foo",
					Username:  "name",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-keybits-to-default-ecdsa",
			origFn: func(csId string) *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					csId,
					"/ssh/sign/foo",
					"name",
					WithKeyType(KeyTypeEcdsa),
					WithKeyBits(KeyBitsEcdsa384),
				)
				return s
			},
			chgFn: changeKeyBits(KeyBitsDefault),
			masks: []string{keyBitsField},
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					KeyType:   KeyTypeEcdsa,
					KeyBits:   KeyBitsEcdsa256,
					VaultPath: "/ssh/sign/foo",
					Username:  "name",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-keybits-to-default-rsa",
			origFn: func(csId string) *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					csId,
					"/ssh/sign/foo",
					"name",
					WithKeyType(KeyTypeRsa),
					WithKeyBits(KeyBitsRsa3072),
				)
				return s
			},
			chgFn: changeKeyBits(KeyBitsDefault),
			masks: []string{keyBitsField},
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					KeyType:   KeyTypeRsa,
					KeyBits:   KeyBitsRsa2048,
					VaultPath: "/ssh/sign/foo",
					Username:  "name",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-ttl",
			origFn: func(csId string) *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					csId,
					"/ssh/sign/foo",
					"name",
					WithTtl("10s"),
				)
				return s
			},
			chgFn: changeTtl("1h"),
			masks: []string{ttlField},
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					Ttl:       "1h",
					VaultPath: "/ssh/sign/foo",
					Username:  "name",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-keyid",
			origFn: func(csId string) *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					csId,
					"/ssh/sign/foo",
					"name",
					WithKeyId("id"),
				)
				return s
			},
			chgFn: changeKeyId("update-id"),
			masks: []string{keyIdField},
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					KeyId:     "update-id",
					VaultPath: "/ssh/sign/foo",
					Username:  "name",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-critical-options",
			origFn: func(csId string) *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					csId,
					"/ssh/sign/foo",
					"name",
					WithCriticalOptions("options"),
				)
				return s
			},
			chgFn: changeCriticalOptions("update-options"),
			masks: []string{CriticalOptionsField},
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					CriticalOptions: "update-options",
					VaultPath:       "/ssh/sign/foo",
					Username:        "name",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-extensions",
			origFn: func(csId string) *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					csId,
					"/ssh/sign/foo",
					"name",
					WithExtensions("extensions"),
				)
				return s
			},
			chgFn: changeExtensions("update-extensions"),
			masks: []string{ExtensionsField},
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					Extensions: "update-extensions",
					VaultPath:  "/ssh/sign/foo",
					Username:   "name",
				},
			},
			wantCount: 1,
		},
		{
			name: "delete-name",
			origFn: func(csId string) *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					csId,
					"/ssh/sign/foo",
					"name",
					WithName("test-name-repo"),
					WithDescription("test-description-repo"),
				)
				return s
			},
			masks: []string{nameField},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("")),
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					VaultPath:   "/ssh/sign/foo",
					Username:    "name",
					Description: "test-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "delete-description",
			origFn: func(csId string) *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					csId,
					"/ssh/sign/foo",
					"name",
					WithName("test-name-repo"),
					WithDescription("test-description-repo"),
				)
				return s
			},
			masks: []string{descriptionField},
			chgFn: combine(changeDescription(""), changeName("test-update-name-repo")),
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					VaultPath: "/ssh/sign/foo",
					Username:  "name",
					Name:      "test-name-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-name",
			origFn: func(csId string) *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					csId,
					"/ssh/sign/foo",
					"name",
					WithName("test-name-repo"),
					WithDescription("test-description-repo"),
				)
				return s
			},
			masks: []string{descriptionField},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("")),
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					VaultPath:   "/ssh/sign/foo",
					Username:    "name",
					Name:        "test-name-repo",
					Description: "test-update-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-description",
			origFn: func(csId string) *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					csId,
					"/ssh/sign/foo",
					"name",
					WithName("test-name-repo"),
					WithDescription("test-description-repo"),
				)
				return s
			},
			masks: []string{nameField},
			chgFn: combine(changeDescription(""), changeName("test-update-name-repo")),
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					VaultPath:   "/ssh/sign/foo",
					Username:    "name",
					Name:        "test-update-name-repo",
					Description: "test-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-vault-path",
			origFn: func(csId string) *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					csId,
					"/ssh/sign/foo",
					"name",
				)
				return s
			},
			chgFn: changeVaultPath("/ssh/issue/foo"),
			masks: []string{vaultPathField},
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					VaultPath: "/ssh/issue/foo",
					Username:  "name",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-vault-path-invalid",
			origFn: func(csId string) *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					csId,
					"/ssh/sign/foo",
					"name",
				)
				return s
			},
			chgFn:   changeVaultPath("/ssh/not-sign/foo"),
			masks:   []string{vaultPathField},
			wantErr: errors.CheckConstraint,
		},
		{
			name: "delete-vault-path",
			origFn: func(csId string) *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					csId,
					"/ssh/sign/foo",
					"name",
				)
				return s
			},
			chgFn:   changeVaultPath(""),
			masks:   []string{vaultPathField},
			wantErr: errors.NotNull,
		},
		{
			name: "change-key-type-invalid",
			origFn: func(csId string) *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					csId,
					"/ssh/sign/foo",
					"name",
					WithKeyType(KeyTypeEcdsa),
					WithKeyBits(KeyBitsEcdsa256),
				)
				return s
			},
			chgFn:   changeKeyType(KeyTypeEd25519),
			masks:   []string{keyTypeField},
			wantErr: errors.NotSpecificIntegrity,
		},
		{
			name: "change-key-type-bits-valid",
			origFn: func(csId string) *SSHCertificateCredentialLibrary {
				s, _ := NewSSHCertificateCredentialLibrary(
					csId,
					"/ssh/sign/foo",
					"name",
					WithKeyType(KeyTypeEcdsa),
					WithKeyBits(KeyBitsEcdsa256),
				)
				return s
			},
			chgFn: combine(changeKeyType(KeyTypeRsa), changeKeyBits(KeyBitsRsa2048)),
			masks: []string{keyTypeField, keyBitsField},
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					VaultPath: "/ssh/sign/foo",
					Username:  "name",
					KeyType:   KeyTypeRsa,
					KeyBits:   KeyBitsRsa2048,
				},
			},
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			kms := kms.TestKms(t, conn, wrapper)
			sche := scheduler.TestScheduler(t, conn, wrapper)
			repo, err := NewRepository(ctx, rw, rw, kms, sche)
			assert.NoError(err)
			require.NotNil(repo)

			_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
			cs := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]

			ttOrig := tt.origFn(cs.GetPublicId())
			orig, err := repo.CreateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), ttOrig)
			assert.NoError(err)
			require.NotNil(orig)

			if tt.chgFn != nil {
				orig = tt.chgFn(orig)
			}
			got, gotCount, err := repo.UpdateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), orig, 1, tt.masks)
			if tt.wantErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				assert.Equal(tt.wantCount, gotCount, "row count")
				assert.Nil(got)
				return
			}
			require.NoError(err)
			assert.Empty(ttOrig.PublicId)
			require.NotNil(got)
			assertPublicId(t, globals.VaultSshCertificateCredentialLibraryPrefix, got.GetPublicId())
			assert.Equal(tt.wantCount, gotCount, "row count")
			assert.NotSame(ttOrig, got)
			assert.Equal(ttOrig.StoreId, got.StoreId)
			underlyingDB, err := conn.SqlDB(ctx)
			require.NoError(err)
			dbassert := dbassert.New(t, underlyingDB)

			switch tt.want.Name {
			case "":
				dbassert.IsNull(got, "name")
			default:
				assert.Equal(tt.want.Name, got.Name)
			}

			switch tt.want.Description {
			case "":
				dbassert.IsNull(got, "description")
			default:
				assert.Equal(tt.want.Description, got.Description)
			}

			switch tt.want.Username {
			case "":
				dbassert.IsNull(got, "Username")
			default:
				assert.Equal(tt.want.Username, got.Username)
			}

			switch tt.want.KeyType {
			case "":
				assert.Equal(got.KeyType, KeyTypeEd25519)
			default:
				assert.Equal(tt.want.KeyType, got.KeyType)
			}

			switch tt.want.KeyBits {
			case (0):
				assert.Zero(got.KeyBits)
			default:
				assert.Equal(tt.want.KeyBits, got.KeyBits)
			}

			switch tt.want.Ttl {
			case "":
				dbassert.IsNull(got, "Ttl")
			default:
				assert.Equal(tt.want.Ttl, got.Ttl)
			}

			switch tt.want.KeyId {
			case "":
				dbassert.IsNull(got, "KeyId")
			default:
				assert.Equal(tt.want.KeyId, got.KeyId)
			}

			switch tt.want.CriticalOptions {
			case "":
				dbassert.IsNull(got, "CriticalOptions")
			default:
				assert.Equal(tt.want.CriticalOptions, got.CriticalOptions)
			}

			switch tt.want.Extensions {
			case "":
				dbassert.IsNull(got, "Extensions")
			default:
				assert.Equal(tt.want.Extensions, got.Extensions)
			}

			if tt.wantCount > 0 {
				assert.NoError(db.TestVerifyOplog(t, rw, got.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
			}
		})
	}

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		sche := scheduler.TestScheduler(t, conn, wrapper)
		repo, err := NewRepository(ctx, rw, rw, kms, sche)
		assert.NoError(err)
		require.NotNil(repo)

		name := "test-dup-name"
		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		cs := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]
		libs := TestSSHCertificateCredentialLibraries(t, conn, wrapper, cs.GetPublicId(), 2)

		lA, lB := libs[0], libs[1]

		lA.Name = name
		got1, gotCount1, err := repo.UpdateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), lA, 1, []string{"name"})
		assert.NoError(err)
		require.NotNil(got1)
		assert.Equal(name, got1.Name)
		assert.Equal(1, gotCount1, "row count")
		assert.NoError(db.TestVerifyOplog(t, rw, lA.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))

		lB.Name = name
		got2, gotCount2, err := repo.UpdateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), lB, 1, []string{"name"})
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "want err code: %v got err: %v", errors.NotUnique, err)
		assert.Nil(got2)
		assert.Equal(db.NoRowsAffected, gotCount2, "row count")
		err = db.TestVerifyOplog(t, rw, lB.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
		assert.Error(err)
		assert.True(errors.IsNotFoundError(err))
	})

	t.Run("valid-duplicate-names-diff-CredentialStores", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		sche := scheduler.TestScheduler(t, conn, wrapper)
		repo, err := NewRepository(ctx, rw, rw, kms, sche)
		assert.NoError(err)
		require.NotNil(repo)

		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		css := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 2)

		csA, csB := css[0], css[1]

		in := &SSHCertificateCredentialLibrary{
			SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
				Username:  "name",
				VaultPath: "/ssh/sign/foo",
				Name:      "test-name-repo",
			},
		}
		in2 := in.clone()

		in.StoreId = csA.GetPublicId()
		got, err := repo.CreateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), in)
		assert.NoError(err)
		require.NotNil(got)
		assertPublicId(t, globals.VaultSshCertificateCredentialLibraryPrefix, got.GetPublicId())
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)

		in2.StoreId = csB.GetPublicId()
		in2.Name = "first-name"
		got2, err := repo.CreateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), in2)
		assert.NoError(err)
		require.NotNil(got2)
		got2.Name = got.Name
		got3, gotCount3, err := repo.UpdateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), got2, 1, []string{"name"})
		assert.NoError(err)
		require.NotNil(got3)
		assert.NotSame(got2, got3)
		assert.Equal(got.Name, got3.Name)
		assert.Equal(got2.Description, got3.Description)
		assert.Equal(1, gotCount3, "row count")
		assert.NoError(db.TestVerifyOplog(t, rw, got2.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
	})

	t.Run("valid-update-with-expired-store-token", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		sche := scheduler.TestScheduler(t, conn, wrapper)
		repo, err := NewRepository(ctx, rw, rw, kms, sche)
		assert.NoError(err)
		require.NotNil(repo)

		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		css := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)
		cs := css[0]

		in := &SSHCertificateCredentialLibrary{
			SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
				Username:  "name",
				VaultPath: "/ssh/sign/foo",
				Name:      "test-name-repo",
			},
		}

		in.StoreId = cs.GetPublicId()
		got, err := repo.CreateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), in)
		assert.NoError(err)
		require.NotNil(got)

		// Expire the credential store Vault token
		rows, err := rw.Exec(context.Background(),
			"update credential_vault_token set status = ? where token_hmac = ?",
			[]any{ExpiredToken, cs.Token().TokenHmac})
		require.NoError(err)
		require.Equal(1, rows)

		got.Name = "new-name"
		updated, gotCount, err := repo.UpdateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), got, 1, []string{"name"})
		assert.NoError(err)
		require.NotNil(updated)
		assert.Equal("new-name", updated.Name)
		assert.Equal(1, gotCount)
	})

	t.Run("change-project-id", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		sche := scheduler.TestScheduler(t, conn, wrapper)
		repo, err := NewRepository(ctx, rw, rw, kms, sche)
		assert.NoError(err)
		require.NotNil(repo)

		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		css := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 2)

		csA, csB := css[0], css[1]

		lA := TestSSHCertificateCredentialLibraries(t, conn, wrapper, csA.GetPublicId(), 1)[0]
		lB := TestSSHCertificateCredentialLibraries(t, conn, wrapper, csB.GetPublicId(), 1)[0]

		assert.NotEqual(lA.StoreId, lB.StoreId)
		orig := lA.clone()

		lA.StoreId = lB.StoreId
		assert.Equal(lA.StoreId, lB.StoreId)

		got1, gotCount1, err := repo.UpdateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), lA, 1, []string{"name"})

		assert.NoError(err)
		require.NotNil(got1)
		assert.Equal(orig.StoreId, got1.StoreId)
		assert.Equal(1, gotCount1, "row count")
		assert.NoError(db.TestVerifyOplog(t, rw, lA.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
	})

	t.Run("change-key-type-bits-consecutive", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		sche := scheduler.TestScheduler(t, conn, wrapper)
		repo, err := NewRepository(ctx, rw, rw, kms, sche)
		assert.NoError(err)
		require.NotNil(repo)

		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		cs := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]

		in := &SSHCertificateCredentialLibrary{
			SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
				Username:  "name",
				VaultPath: "/ssh/sign/foo",
				KeyType:   KeyTypeEcdsa,
				KeyBits:   KeyBitsEcdsa521,
			},
		}
		in.StoreId = cs.GetPublicId()

		orig, err := repo.CreateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), in)
		assert.NoError(err)
		require.NotNil(orig)

		orig.KeyBits = KeyBitsEcdsa256

		got, gotCount, err := repo.UpdateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), orig, 1, []string{keyBitsField})
		require.NoError(err)
		assert.Empty(in.PublicId)
		require.NotNil(got)
		assertPublicId(t, globals.VaultSshCertificateCredentialLibraryPrefix, got.GetPublicId())
		assert.Equal(1, gotCount, "row count")
		assert.NotSame(orig, got)
		assert.Equal(orig.StoreId, got.StoreId)

		orig.KeyType = KeyTypeRsa
		orig.KeyBits = KeyBitsDefault

		got, gotCount, err = repo.UpdateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), orig, 2, []string{keyTypeField, keyBitsField})
		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, globals.VaultSshCertificateCredentialLibraryPrefix, got.GetPublicId())
		assert.Equal(1, gotCount, "row count")
		assert.NotSame(orig, got)
		assert.Equal(orig.StoreId, got.StoreId)

		orig.KeyBits = KeyBitsRsa3072

		got, gotCount, err = repo.UpdateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), orig, 3, []string{keyTypeField})
		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, globals.VaultSshCertificateCredentialLibraryPrefix, got.GetPublicId())
		assert.Equal(1, gotCount, "row count")
		assert.NotSame(orig, got)
		assert.Equal(orig.StoreId, got.StoreId)

		assert.Equal(KeyTypeRsa, orig.KeyType)
		assert.Equal(uint32(KeyBitsRsa3072), orig.KeyBits)
	})
}

func TestRepository_DeleteSSHCertificateCredentialLibrary(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	{
		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		cs := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]
		l := TestSSHCertificateCredentialLibraries(t, conn, wrapper, cs.GetPublicId(), 1)[0]

		badId, err := newSSHCertificateCredentialLibraryId(ctx)
		require.NoError(t, err)
		require.NotNil(t, badId)

		tests := []struct {
			name    string
			in      string
			want    int
			wantErr errors.Code
		}{
			{
				name: "found",
				in:   l.GetPublicId(),
				want: 1,
			},
			{
				name: "not-found",
				in:   badId,
			},
			{
				name:    "empty-public-id",
				in:      "",
				wantErr: errors.InvalidParameter,
			},
		}

		for _, tt := range tests {
			tt := tt
			t.Run(tt.name, func(t *testing.T) {
				assert, require := assert.New(t), require.New(t)
				kms := kms.TestKms(t, conn, wrapper)
				sche := scheduler.TestScheduler(t, conn, wrapper)
				repo, err := NewRepository(ctx, rw, rw, kms, sche)
				assert.NoError(err)
				require.NotNil(repo)

				got, err := repo.DeleteSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), tt.in)
				if tt.wantErr != 0 {
					assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
					return
				}
				assert.NoError(err)
				assert.Equal(tt.want, got, "row count")

				cl, err := repo.LookupSSHCertificateCredentialLibrary(ctx, tt.in)
				assert.Empty(err)
				assert.Empty(cl)
			})
		}
	}
}
