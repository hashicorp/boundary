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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_CreateCredentialLibrary(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cs := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]

	tests := []struct {
		name    string
		in      *CredentialLibrary
		opts    []Option
		want    *CredentialLibrary
		wantErr errors.Code
	}{
		{
			name:    "nil-CredentialLibrary",
			wantErr: errors.InvalidParameter,
		},
		{
			name:    "nil-embedded-CredentialLibrary",
			in:      &CredentialLibrary{},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "invalid-no-store-id",
			in: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{},
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "invalid-public-id-set",
			in: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:  cs.GetPublicId(),
					PublicId: "abcd_OOOOOOOOOO",
				},
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "invalid-no-vault-path",
			in: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					StoreId: cs.GetPublicId(),
				},
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "valid-no-options",
			in: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:   cs.GetPublicId(),
					VaultPath: "/some/path",
				},
			},
			want: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:   cs.GetPublicId(),
					VaultPath: "/some/path",
				},
			},
		},
		{
			name: "valid-with-name",
			in: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:   cs.GetPublicId(),
					Name:      "test-name-repo",
					VaultPath: "/some/path",
				},
			},
			want: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:   cs.GetPublicId(),
					Name:      "test-name-repo",
					VaultPath: "/some/path",
				},
			},
		},
		{
			name: "valid-with-description",
			in: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:     cs.GetPublicId(),
					Description: ("test-description-repo"),
					VaultPath:   "/some/path",
				},
			},
			want: &CredentialLibrary{
				CredentialLibrary: &store.CredentialLibrary{
					StoreId:     cs.GetPublicId(),
					Description: ("test-description-repo"),
					VaultPath:   "/some/path",
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
			repo, err := NewRepository(rw, rw, kms)
			require.NoError(err)
			require.NotNil(repo)
			got, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), tt.in, tt.opts...)
			if tt.wantErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			assert.Empty(tt.in.PublicId)
			require.NotNil(got)
			assertPublicId(t, CredentialLibraryPrefix, got.GetPublicId())
			assert.NotSame(tt.in, got)
			assert.Equal(tt.want.Name, got.Name)
			assert.Equal(tt.want.Description, got.Description)
			assert.Equal(got.CreateTime, got.UpdateTime)
			assert.NoError(db.TestVerifyOplog(t, rw, got.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))
		})
	}

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		repo, err := NewRepository(rw, rw, kms)
		require.NoError(err)
		require.NotNil(repo)
		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		cs := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]
		in := &CredentialLibrary{
			CredentialLibrary: &store.CredentialLibrary{
				StoreId:   cs.GetPublicId(),
				VaultPath: "/some/path",
				Name:      "test-name-repo",
			},
		}

		got, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), in)
		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, CredentialLibraryPrefix, got.GetPublicId())
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		got2, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), in)
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "want err: %q got: %q", errors.NotUnique, err)
		assert.Nil(got2)
	})

	t.Run("valid-duplicate-names-diff-stores", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		repo, err := NewRepository(rw, rw, kms)
		require.NoError(err)
		require.NotNil(repo)

		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		css := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 2)

		csA, csB := css[0], css[1]

		in := &CredentialLibrary{
			CredentialLibrary: &store.CredentialLibrary{
				VaultPath: "/some/path",
				Name:      "test-name-repo",
			},
		}
		in2 := in.clone()

		in.StoreId = csA.GetPublicId()
		got, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), in)
		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, CredentialLibraryPrefix, got.GetPublicId())
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		in2.StoreId = csB.GetPublicId()
		got2, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), in2)
		require.NoError(err)
		require.NotNil(got2)
		assertPublicId(t, CredentialLibraryPrefix, got2.GetPublicId())
		assert.NotSame(in2, got2)
		assert.Equal(in2.Name, got2.Name)
		assert.Equal(in2.Description, got2.Description)
		assert.Equal(got2.CreateTime, got2.UpdateTime)
	})
}
