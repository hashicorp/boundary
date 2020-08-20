package static

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/host/static/store"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_CreateSet(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	_, prj := iam.TestScopes(t, conn)
	catalog := testCatalogs(t, conn, prj.PublicId, 1)[0]

	var tests = []struct {
		name      string
		in        *HostSet
		opts      []Option
		want      *HostSet
		wantIsErr error
	}{
		{
			name:      "nil-HostSet",
			wantIsErr: db.ErrNilParameter,
		},
		{
			name:      "nil-embedded-HostSet",
			in:        &HostSet{},
			wantIsErr: db.ErrNilParameter,
		},
		{
			name: "invalid-no-catalog-id",
			in: &HostSet{
				HostSet: &store.HostSet{},
			},
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "invalid-public-id-set",
			in: &HostSet{
				HostSet: &store.HostSet{
					CatalogId: catalog.PublicId,
					PublicId:  "abcd_OOOOOOOOOO",
				},
			},
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "valid-no-options",
			in: &HostSet{
				HostSet: &store.HostSet{
					CatalogId: catalog.PublicId,
				},
			},
			want: &HostSet{
				HostSet: &store.HostSet{
					CatalogId: catalog.PublicId,
				},
			},
		},
		{
			name: "valid-with-name",
			in: &HostSet{
				HostSet: &store.HostSet{
					CatalogId: catalog.PublicId,
					Name:      "test-name-repo",
				},
			},
			want: &HostSet{
				HostSet: &store.HostSet{
					CatalogId: catalog.PublicId,
					Name:      "test-name-repo",
				},
			},
		},
		{
			name: "valid-with-description",
			in: &HostSet{
				HostSet: &store.HostSet{
					CatalogId:   catalog.PublicId,
					Description: ("test-description-repo"),
				},
			},
			want: &HostSet{
				HostSet: &store.HostSet{
					CatalogId:   catalog.PublicId,
					Description: ("test-description-repo"),
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, wrapper)
			require.NoError(err)
			require.NotNil(repo)
			got, err := repo.CreateSet(context.Background(), tt.in, tt.opts...)
			if tt.wantIsErr != nil {
				assert.Truef(errors.Is(err, tt.wantIsErr), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			assert.Empty(tt.in.PublicId)
			require.NotNil(got)
			assertPublicId(t, HostSetPrefix, got.PublicId)
			assert.NotSame(tt.in, got)
			assert.Equal(tt.want.Name, got.Name)
			assert.Equal(tt.want.Description, got.Description)
			assert.Equal(got.CreateTime, got.UpdateTime)
			assert.NoError(db.TestVerifyOplog(t, rw, got.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))
		})
	}

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(rw, rw, wrapper)
		require.NoError(err)
		require.NotNil(repo)

		_, prj := iam.TestScopes(t, conn)
		catalog := testCatalogs(t, conn, prj.PublicId, 1)[0]

		in := &HostSet{
			HostSet: &store.HostSet{
				CatalogId: catalog.PublicId,
				Name:      "test-name-repo",
			},
		}

		got, err := repo.CreateSet(context.Background(), in)
		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, HostSetPrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		got2, err := repo.CreateSet(context.Background(), in)
		assert.Truef(errors.Is(err, db.ErrNotUnique), "want err: %v got: %v", db.ErrNotUnique, err)
		assert.Nil(got2)
	})

	t.Run("valid-duplicate-names-diff-catalogs", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(rw, rw, wrapper)
		require.NoError(err)
		require.NotNil(repo)

		_, prj := iam.TestScopes(t, conn)
		catalogs := testCatalogs(t, conn, prj.PublicId, 2)

		catalogA, catalogB := catalogs[0], catalogs[1]

		in := &HostSet{
			HostSet: &store.HostSet{
				Name: "test-name-repo",
			},
		}
		in2 := in.clone()

		in.CatalogId = catalogA.PublicId
		got, err := repo.CreateSet(context.Background(), in)
		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, HostSetPrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		in2.CatalogId = catalogB.PublicId
		got2, err := repo.CreateSet(context.Background(), in2)
		require.NoError(err)
		require.NotNil(got2)
		assertPublicId(t, HostSetPrefix, got2.PublicId)
		assert.NotSame(in2, got2)
		assert.Equal(in2.Name, got2.Name)
		assert.Equal(in2.Description, got2.Description)
		assert.Equal(got2.CreateTime, got2.UpdateTime)
	})
}
