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

func TestRepository_CreateHost(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	_, prj := iam.TestScopes(t, conn)
	catalog := testCatalogs(t, conn, prj.PublicId, 1)[0]

	var tests = []struct {
		name      string
		in        *Host
		opts      []Option
		want      *Host
		wantIsErr error
	}{
		{
			name:      "nil-Host",
			wantIsErr: db.ErrNilParameter,
		},
		{
			name:      "nil-embedded-Host",
			in:        &Host{},
			wantIsErr: db.ErrNilParameter,
		},
		{
			name: "invalid-no-catalog-id",
			in: &Host{
				Host: &store.Host{},
			},
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "invalid-public-id-set",
			in: &Host{
				Host: &store.Host{
					CatalogId: catalog.PublicId,
					PublicId:  "abcd_OOOOOOOOOO",
					Address:   "127.0.0.1",
				},
			},
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "valid-no-options",
			in: &Host{
				Host: &store.Host{
					CatalogId: catalog.PublicId,
					Address:   "127.0.0.1",
				},
			},
			want: &Host{
				Host: &store.Host{
					CatalogId: catalog.PublicId,
					Address:   "127.0.0.1",
				},
			},
		},
		{
			name: "valid-with-name",
			in: &Host{
				Host: &store.Host{
					CatalogId: catalog.PublicId,
					Name:      "test-name-repo",
					Address:   "127.0.0.1",
				},
			},
			want: &Host{
				Host: &store.Host{
					CatalogId: catalog.PublicId,
					Name:      "test-name-repo",
					Address:   "127.0.0.1",
				},
			},
		},
		{
			name: "valid-with-description",
			in: &Host{
				Host: &store.Host{
					CatalogId:   catalog.PublicId,
					Description: ("test-description-repo"),
					Address:     "127.0.0.1",
				},
			},
			want: &Host{
				Host: &store.Host{
					CatalogId:   catalog.PublicId,
					Description: ("test-description-repo"),
					Address:     "127.0.0.1",
				},
			},
		},
		{
			name: "invalid-no-address",
			in: &Host{
				Host: &store.Host{
					CatalogId: catalog.PublicId,
				},
			},
			wantIsErr: ErrInvalidAddress,
		},
		{
			name: "invalid-address-to-short",
			in: &Host{
				Host: &store.Host{
					CatalogId: catalog.PublicId,
					Address:   "127",
				},
			},
			wantIsErr: ErrInvalidAddress,
		},
		{
			name: "invalid-empty-address",
			in: &Host{
				Host: &store.Host{
					CatalogId: catalog.PublicId,
					Address:   "            ",
				},
			},
			wantIsErr: ErrInvalidAddress,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, wrapper)
			require.NoError(err)
			require.NotNil(repo)
			got, err := repo.CreateHost(context.Background(), tt.in, tt.opts...)
			if tt.wantIsErr != nil {
				assert.Truef(errors.Is(err, tt.wantIsErr), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			assert.Empty(tt.in.PublicId)
			require.NotNil(got)
			assertPublicId(t, HostPrefix, got.PublicId)
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

		in := &Host{
			Host: &store.Host{
				CatalogId: catalog.PublicId,
				Name:      "test-name-repo",
				Address:   "127.0.0.1",
			},
		}

		got, err := repo.CreateHost(context.Background(), in)
		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, HostPrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		got2, err := repo.CreateHost(context.Background(), in)
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

		in := &Host{
			Host: &store.Host{
				Name:    "test-name-repo",
				Address: "127.0.0.1",
			},
		}
		in2 := in.clone()

		in.CatalogId = catalogA.PublicId
		got, err := repo.CreateHost(context.Background(), in)
		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, HostPrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		in2.CatalogId = catalogB.PublicId
		got2, err := repo.CreateHost(context.Background(), in2)
		require.NoError(err)
		require.NotNil(got2)
		assertPublicId(t, HostPrefix, got2.PublicId)
		assert.NotSame(in2, got2)
		assert.Equal(in2.Name, got2.Name)
		assert.Equal(in2.Description, got2.Description)
		assert.Equal(got2.CreateTime, got2.UpdateTime)
	})
}
