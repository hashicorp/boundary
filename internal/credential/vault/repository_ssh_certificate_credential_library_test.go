package vault

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/db"
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
			in: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{},
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "invalid-public-id-set",
			in: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					StoreId:  cs.GetPublicId(),
					PublicId: "abcd_OOOOOOOOOO",
				},
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "invalid-no-username",
			in: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					StoreId:   cs.GetPublicId(),
					VaultPath: "/some/path",
				},
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "invalid-no-vault-path",
			in: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					StoreId:   cs.GetPublicId(),
					VaultPath: "/some/path",
				},
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "valid-no-options",
			in: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					StoreId:   cs.GetPublicId(),
					KeyType:   "ed25519",
					VaultPath: "/some/path",
					Username:  "admin",
				},
			},
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					StoreId:   cs.GetPublicId(),
					KeyType:   "ed25519",
					VaultPath: "/some/path",
					Username:  "admin",
				},
			},
		},
		{
			name: "valid-with-name",
			in: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					StoreId:   cs.GetPublicId(),
					KeyType:   "ed25519",
					Name:      "test-name-repo",
					VaultPath: "/some/path",
					Username:  "admin",
				},
			},
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					StoreId:   cs.GetPublicId(),
					KeyType:   "ed25519",
					Name:      "test-name-repo",
					VaultPath: "/some/path",
					Username:  "admin",
				},
			},
		},
		{
			name: "valid-with-description",
			in: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					StoreId:     cs.GetPublicId(),
					KeyType:     "ed25519",
					Description: "test-description-repo",
					VaultPath:   "/some/path",
					Username:    "admin",
				},
			},
			want: &SSHCertificateCredentialLibrary{
				SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
					StoreId:     cs.GetPublicId(),
					KeyType:     "ed25519",
					Description: "test-description-repo",
					VaultPath:   "/some/path",
					Username:    "admin",
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
			repo, err := NewRepository(rw, rw, kms, sche)
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
			assertPublicId(t, SSHCertificateCredentialLibraryPrefix, got.GetPublicId())
			assert.NotSame(tt.in, got)
			assert.Equal(tt.want.Name, got.Name)
			assert.Equal(tt.want.Description, got.Description)
			assert.Equal(tt.want.CredentialType(), got.CredentialType())
			assert.Equal(got.CreateTime, got.UpdateTime)

			assert.NoError(db.TestVerifyOplog(t, rw, got.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))

			if tt.in.MappingOverride != nil {
				require.NotNil(got.MappingOverride)
				assert.IsType(tt.want.MappingOverride, got.MappingOverride)
				switch w := tt.want.MappingOverride.(type) {
				case *UsernamePasswordOverride:
					g, ok := got.MappingOverride.(*UsernamePasswordOverride)
					require.True(ok)
					assert.Equal(w.UsernameAttribute, g.UsernameAttribute)
					assert.Equal(w.PasswordAttribute, g.PasswordAttribute)

					// verify it was persisted in the database
					override := allocUsernamePasswordOverride()
					assert.NoError(rw.LookupWhere(ctx, &override, "library_id = ?", []any{got.GetPublicId()}))

				case *SshPrivateKeyOverride:
					g, ok := got.MappingOverride.(*SshPrivateKeyOverride)
					require.True(ok)
					assert.Equal(w.UsernameAttribute, g.UsernameAttribute)
					assert.Equal(w.PrivateKeyAttribute, g.PrivateKeyAttribute)
					assert.Equal(w.PrivateKeyPassphraseAttribute, g.PrivateKeyPassphraseAttribute)

					// verify it was persisted in the database
					override := allocSshPrivateKeyOverride()
					assert.NoError(rw.LookupWhere(ctx, &override, "library_id = ?", []any{got.GetPublicId()}))

				default:
					assert.Fail("Unknown mapping override")
				}
			}
		})
	}

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		sche := scheduler.TestScheduler(t, conn, wrapper)
		repo, err := NewRepository(rw, rw, kms, sche)
		require.NoError(err)
		require.NotNil(repo)
		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		cs := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]
		in := &SSHCertificateCredentialLibrary{
			SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
				StoreId:   cs.GetPublicId(),
				KeyType:   "ed25519",
				VaultPath: "/some/path",
				Name:      "test-name-repo",
				Username:  "admin",
			},
		}

		got, err := repo.CreateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), in)
		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, SSHCertificateCredentialLibraryPrefix, got.GetPublicId())
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
		repo, err := NewRepository(rw, rw, kms, sche)
		require.NoError(err)
		require.NotNil(repo)

		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		css := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 2)

		csA, csB := css[0], css[1]

		in := &SSHCertificateCredentialLibrary{
			SSHCertificateCredentialLibrary: &store.SSHCertificateCredentialLibrary{
				KeyType:   "ed25519",
				VaultPath: "/some/path",
				Name:      "test-name-repo",
				Username:  "admin",
			},
		}
		in2 := in.clone()

		in.StoreId = csA.GetPublicId()
		got, err := repo.CreateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), in)
		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, SSHCertificateCredentialLibraryPrefix, got.GetPublicId())
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		in2.StoreId = csB.GetPublicId()
		got2, err := repo.CreateSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), in2)
		require.NoError(err)
		require.NotNil(got2)
		assertPublicId(t, SSHCertificateCredentialLibraryPrefix, got2.GetPublicId())
		assert.NotSame(in2, got2)
		assert.Equal(in2.Name, got2.Name)
		assert.Equal(in2.Description, got2.Description)
		assert.Equal(got2.CreateTime, got2.UpdateTime)
	})
}
