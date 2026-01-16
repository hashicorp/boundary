// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package static

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	dbassert "github.com/hashicorp/boundary/internal/db/assert"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/static/store"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestRepository_CreateHost(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iamRepo)
	catalog := TestCatalogs(t, conn, prj.PublicId, 1)[0]

	tests := []struct {
		name      string
		in        *Host
		opts      []Option
		want      *Host
		wantIsErr errors.Code
	}{
		{
			name:      "nil-Host",
			wantIsErr: errors.InvalidParameter,
		},
		{
			name:      "nil-embedded-Host",
			in:        &Host{},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "invalid-no-catalog-id",
			in: &Host{
				Host: &store.Host{},
			},
			wantIsErr: errors.InvalidParameter,
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
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "valid-dns-name",
			in: &Host{
				Host: &store.Host{
					CatalogId: catalog.PublicId,
					Address:   "www.google.com",
				},
			},
			want: &Host{
				Host: &store.Host{
					CatalogId: catalog.PublicId,
					Address:   "www.google.com",
				},
			},
		},
		{
			name: "valid-ipv4-address",
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
			name: "invalid-ipv4-address-with-port",
			in: &Host{
				Host: &store.Host{
					CatalogId: catalog.PublicId,
					Address:   "127.0.0.1:80",
				},
			},
			wantIsErr: errors.InvalidAddress,
		},
		{
			name: "valid-abbreviated-ipv6-address",
			in: &Host{
				Host: &store.Host{
					CatalogId: catalog.PublicId,
					Address:   "2001:4860:4860::8888",
				},
			},
			want: &Host{
				Host: &store.Host{
					CatalogId: catalog.PublicId,
					Address:   "2001:4860:4860::8888",
				},
			},
		},
		{
			name: "invalid-abbreviated-ipv6-address-with-port",
			in: &Host{
				Host: &store.Host{
					CatalogId: catalog.PublicId,
					Address:   "[2001:4860:4860::8888]:80",
				},
			},
			wantIsErr: errors.InvalidAddress,
		},
		{
			name: "valid-ipv6-address",
			in: &Host{
				Host: &store.Host{
					CatalogId: catalog.PublicId,
					Address:   "2001:4860:4860:0:0:0:0:8888",
				},
			},
			want: &Host{
				Host: &store.Host{
					CatalogId: catalog.PublicId,
					Address:   "2001:4860:4860::8888",
				},
			},
		},
		{
			name: "invalid-ipv6-address-with-port",
			in: &Host{
				Host: &store.Host{
					CatalogId: catalog.PublicId,
					Address:   "[2001:4860:4860:0:0:0:0:8888]:80",
				},
			},
			wantIsErr: errors.InvalidAddress,
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
			wantIsErr: errors.InvalidAddress,
		},
		{
			name: "invalid-address-to-short",
			in: &Host{
				Host: &store.Host{
					CatalogId: catalog.PublicId,
					Address:   "12",
				},
			},
			wantIsErr: errors.InvalidAddress,
		},
		{
			name: "invalid-empty-address",
			in: &Host{
				Host: &store.Host{
					CatalogId: catalog.PublicId,
					Address:   "            ",
				},
			},
			wantIsErr: errors.InvalidAddress,
		},
		{
			name: "invalid_public_id",
			in: &Host{
				Host: &store.Host{
					CatalogId: catalog.PublicId,
					Address:   "127.0.0.1",
				},
			},
			opts:      []Option{WithPublicId("bad_prefix")},
			wantIsErr: errors.InvalidPublicId,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kms)
			require.NoError(err)
			require.NotNil(repo)
			got, err := repo.CreateHost(ctx, prj.GetPublicId(), tt.in, tt.opts...)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			assert.Empty(tt.in.PublicId)
			require.NotNil(got)
			assertPublicId(t, globals.StaticHostPrefix, got.PublicId)
			assert.NotSame(tt.in, got)
			assert.Equal(tt.want.Name, got.Name)
			assert.Equal(tt.want.Description, got.Description)
			assert.Equal(got.CreateTime, got.UpdateTime)
			assert.NoError(db.TestVerifyOplog(t, rw, got.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))
		})
	}

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(ctx, rw, rw, kms)
		require.NoError(err)
		require.NotNil(repo)

		_, prj := iam.TestScopes(t, iamRepo)
		catalog := TestCatalogs(t, conn, prj.PublicId, 1)[0]

		in := &Host{
			Host: &store.Host{
				CatalogId: catalog.PublicId,
				Name:      "test-name-repo",
				Address:   "127.0.0.1",
			},
		}

		got, err := repo.CreateHost(ctx, prj.GetPublicId(), in)
		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, globals.StaticHostPrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		got2, err := repo.CreateHost(ctx, prj.GetPublicId(), in)
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "want err code: %v got err: %v", errors.NotUnique, err)
		assert.Nil(got2)
	})

	t.Run("valid-duplicate-names-diff-catalogs", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(ctx, rw, rw, kms)
		require.NoError(err)
		require.NotNil(repo)

		_, prj := iam.TestScopes(t, iamRepo)
		catalogs := TestCatalogs(t, conn, prj.PublicId, 2)

		catalogA, catalogB := catalogs[0], catalogs[1]

		in := &Host{
			Host: &store.Host{
				Name:    "test-name-repo",
				Address: "127.0.0.1",
			},
		}
		in2 := in.clone()

		in.CatalogId = catalogA.PublicId
		got, err := repo.CreateHost(ctx, prj.GetPublicId(), in)
		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, globals.StaticHostPrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		in2.CatalogId = catalogB.PublicId
		got2, err := repo.CreateHost(ctx, prj.GetPublicId(), in2)
		require.NoError(err)
		require.NotNil(got2)
		assertPublicId(t, globals.StaticHostPrefix, got2.PublicId)
		assert.NotSame(in2, got2)
		assert.Equal(in2.Name, got2.Name)
		assert.Equal(in2.Description, got2.Description)
		assert.Equal(got2.CreateTime, got2.UpdateTime)
	})
}

func TestRepository_UpdateHost(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	changeAddress := func(s string) func(*Host) *Host {
		return func(h *Host) *Host {
			h.Address = s
			return h
		}
	}

	changeName := func(s string) func(*Host) *Host {
		return func(h *Host) *Host {
			h.Name = s
			return h
		}
	}

	changeDescription := func(s string) func(*Host) *Host {
		return func(h *Host) *Host {
			h.Description = s
			return h
		}
	}

	makeNil := func() func(*Host) *Host {
		return func(h *Host) *Host {
			return nil
		}
	}

	makeEmbeddedNil := func() func(*Host) *Host {
		return func(h *Host) *Host {
			return &Host{}
		}
	}

	deletePublicId := func() func(*Host) *Host {
		return func(h *Host) *Host {
			h.PublicId = ""
			return h
		}
	}

	nonExistentPublicId := func() func(*Host) *Host {
		return func(h *Host) *Host {
			h.PublicId = "abcd_OOOOOOOOOO"
			return h
		}
	}

	combine := func(fns ...func(h *Host) *Host) func(*Host) *Host {
		return func(h *Host) *Host {
			for _, fn := range fns {
				h = fn(h)
			}
			return h
		}
	}

	tests := []struct {
		name      string
		orig      *Host
		chgFn     func(*Host) *Host
		masks     []string
		want      *Host
		wantCount int
		wantIsErr errors.Code
	}{
		{
			name: "nil-host",
			orig: &Host{
				Host: &store.Host{
					Address: "127.0.0.1",
				},
			},
			chgFn:     makeNil(),
			masks:     []string{"Name", "Description"},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "nil-embedded-host",
			orig: &Host{
				Host: &store.Host{
					Address: "127.0.0.1",
				},
			},
			chgFn:     makeEmbeddedNil(),
			masks:     []string{"Name", "Description"},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "no-public-id",
			orig: &Host{
				Host: &store.Host{
					Address: "127.0.0.1",
				},
			},
			chgFn:     deletePublicId(),
			masks:     []string{"Name", "Description"},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "updating-non-existent-host",
			orig: &Host{
				Host: &store.Host{
					Name:    "test-name-repo",
					Address: "127.0.0.1",
				},
			},
			chgFn:     combine(nonExistentPublicId(), changeName("test-update-name-repo")),
			masks:     []string{"Name"},
			wantIsErr: errors.RecordNotFound,
		},
		{
			name: "empty-field-mask",
			orig: &Host{
				Host: &store.Host{
					Name:    "test-name-repo",
					Address: "127.0.0.1",
				},
			},
			chgFn:     changeName("test-update-name-repo"),
			wantIsErr: errors.EmptyFieldMask,
		},
		{
			name: "read-only-fields-in-field-mask",
			orig: &Host{
				Host: &store.Host{
					Name:    "test-name-repo",
					Address: "127.0.0.1",
				},
			},
			chgFn:     changeName("test-update-name-repo"),
			masks:     []string{"PublicId", "CreateTime", "UpdateTime", "CatalogId"},
			wantIsErr: errors.InvalidFieldMask,
		},
		{
			name: "unknown-field-in-field-mask",
			orig: &Host{
				Host: &store.Host{
					Name:    "test-name-repo",
					Address: "127.0.0.1",
				},
			},
			chgFn:     changeName("test-update-name-repo"),
			masks:     []string{"Bilbo"},
			wantIsErr: errors.InvalidFieldMask,
		},
		{
			name: "change-name",
			orig: &Host{
				Host: &store.Host{
					Name:    "test-name-repo",
					Address: "127.0.0.1",
				},
			},
			chgFn: changeName("test-update-name-repo"),
			masks: []string{"Name"},
			want: &Host{
				Host: &store.Host{
					Name:    "test-update-name-repo",
					Address: "127.0.0.1",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-description",
			orig: &Host{
				Host: &store.Host{
					Description: "test-description-repo",
					Address:     "127.0.0.1",
				},
			},
			chgFn: changeDescription("test-update-description-repo"),
			masks: []string{"Description"},
			want: &Host{
				Host: &store.Host{
					Description: "test-update-description-repo",
					Address:     "127.0.0.1",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-name-and-description",
			orig: &Host{
				Host: &store.Host{
					Name:        "test-name-repo",
					Description: "test-description-repo",
					Address:     "127.0.0.1",
				},
			},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("test-update-name-repo")),
			masks: []string{"Name", "Description"},
			want: &Host{
				Host: &store.Host{
					Name:        "test-update-name-repo",
					Description: "test-update-description-repo",
					Address:     "127.0.0.1",
				},
			},
			wantCount: 1,
		},
		{
			name: "delete-name",
			orig: &Host{
				Host: &store.Host{
					Name:        "test-name-repo",
					Description: "test-description-repo",
					Address:     "127.0.0.1",
				},
			},
			masks: []string{"Name"},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("")),
			want: &Host{
				Host: &store.Host{
					Description: "test-description-repo",
					Address:     "127.0.0.1",
				},
			},
			wantCount: 1,
		},
		{
			name: "delete-description",
			orig: &Host{
				Host: &store.Host{
					Name:        "test-name-repo",
					Description: "test-description-repo",
					Address:     "127.0.0.1",
				},
			},
			masks: []string{"Description"},
			chgFn: combine(changeDescription(""), changeName("test-update-name-repo")),
			want: &Host{
				Host: &store.Host{
					Name:    "test-name-repo",
					Address: "127.0.0.1",
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-name",
			orig: &Host{
				Host: &store.Host{
					Name:        "test-name-repo",
					Description: "test-description-repo",
					Address:     "127.0.0.1",
				},
			},
			masks: []string{"Description"},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("")),
			want: &Host{
				Host: &store.Host{
					Name:        "test-name-repo",
					Description: "test-update-description-repo",
					Address:     "127.0.0.1",
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-description",
			orig: &Host{
				Host: &store.Host{
					Name:        "test-name-repo",
					Description: "test-description-repo",
					Address:     "127.0.0.1",
				},
			},
			masks: []string{"Name"},
			chgFn: combine(changeDescription(""), changeName("test-update-name-repo")),
			want: &Host{
				Host: &store.Host{
					Name:        "test-update-name-repo",
					Description: "test-description-repo",
					Address:     "127.0.0.1",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-dns-name",
			orig: &Host{
				Host: &store.Host{
					Address: "www.google.com",
				},
			},
			chgFn: changeAddress("www.hashicorp.com"),
			masks: []string{"Address"},
			want: &Host{
				Host: &store.Host{
					Address: "www.hashicorp.com",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-ipv4-address",
			orig: &Host{
				Host: &store.Host{
					Address: "127.0.0.1",
				},
			},
			chgFn: changeAddress("10.0.0.1"),
			masks: []string{"Address"},
			want: &Host{
				Host: &store.Host{
					Address: "10.0.0.1",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-invalid-ipv4-address",
			orig: &Host{
				Host: &store.Host{
					Address: "127.0.0.1",
				},
			},
			chgFn:     changeAddress("10.0.0.1:80"),
			masks:     []string{"Address"},
			wantIsErr: errors.InvalidAddress,
		},
		{
			name: "change-invalid-abbreviated-ipv6-address",
			orig: &Host{
				Host: &store.Host{
					Address: "127.0.0.1",
				},
			},
			chgFn:     changeAddress("[2001:4860:4860::8888]:80"),
			masks:     []string{"Address"},
			wantIsErr: errors.InvalidAddress,
		},
		{
			name: "change-invalid-ipv6-address",
			orig: &Host{
				Host: &store.Host{
					Address: "127.0.0.1",
				},
			},
			chgFn:     changeAddress("[2001:4860:4860:0:0:0:0:8888]:80"),
			masks:     []string{"Address"},
			wantIsErr: errors.InvalidAddress,
		},
		{
			name: "change-abbreviated-ipv6-address",
			orig: &Host{
				Host: &store.Host{
					Address: "127.0.0.1",
				},
			},
			chgFn: changeAddress("2001:4860:4860::8888"),
			masks: []string{"Address"},
			want: &Host{
				Host: &store.Host{
					Address: "2001:4860:4860::8888",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-ipv6-address",
			orig: &Host{
				Host: &store.Host{
					Address: "127.0.0.1",
				},
			},
			chgFn: changeAddress("2001:4860:4860:0:0:0:0:8888"),
			masks: []string{"Address"},
			want: &Host{
				Host: &store.Host{
					Address: "2001:4860:4860::8888",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-short-address",
			orig: &Host{
				Host: &store.Host{
					Address: "127.0.0.1",
				},
			},
			chgFn:     changeAddress("11"),
			masks:     []string{"Address"},
			wantIsErr: errors.InvalidAddress,
		},
		{
			name: "delete-address",
			orig: &Host{
				Host: &store.Host{
					Address: "127.0.0.1",
				},
			},
			chgFn:     changeAddress(""),
			masks:     []string{"Address"},
			wantIsErr: errors.InvalidAddress,
		},
		{
			name: "change-empty-address",
			orig: &Host{
				Host: &store.Host{
					Address: "127.0.0.1",
				},
			},
			chgFn:     changeAddress("            "),
			masks:     []string{"Address"},
			wantIsErr: errors.InvalidAddress,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)

			_, prj := iam.TestScopes(t, iamRepo)
			catalog := TestCatalogs(t, conn, prj.PublicId, 1)[0]

			tt.orig.CatalogId = catalog.PublicId
			orig, err := repo.CreateHost(ctx, prj.GetPublicId(), tt.orig)
			assert.NoError(err)
			require.NotNil(orig)

			set := TestSets(t, conn, catalog.GetPublicId(), 1)[0]
			TestSetMembers(t, conn, set.PublicId, []*Host{orig})
			wantSetIds := []string{set.PublicId}

			if tt.chgFn != nil {
				orig = tt.chgFn(orig)
			}
			got, gotCount, err := repo.UpdateHost(ctx, prj.GetPublicId(), orig, 1, tt.masks)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Equal(tt.wantCount, gotCount, "row count")
				assert.Nil(got)
				return
			}
			assert.NoError(err)
			assert.Empty(tt.orig.PublicId)
			require.NotNil(got)
			assertPublicId(t, globals.StaticHostPrefix, got.PublicId)
			assert.Equal(tt.wantCount, gotCount, "row count")
			assert.NotSame(tt.orig, got)
			assert.Equal(tt.orig.CatalogId, got.CatalogId)
			underlyingDB, err := conn.SqlDB(ctx)
			require.NoError(err)
			dbassert := dbassert.New(t, underlyingDB)
			if tt.want.Name == "" {
				dbassert.IsNull(got, "name")
				return
			}
			assert.Equal(wantSetIds, got.SetIds)
			assert.Equal(tt.want.Name, got.Name)
			if tt.want.Description == "" {
				dbassert.IsNull(got, "description")
				return
			}
			assert.Equal(tt.want.Description, got.Description)
			if tt.wantCount > 0 {
				assert.NoError(db.TestVerifyOplog(t, rw, got.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
			}
		})
	}

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(ctx, rw, rw, kms)
		assert.NoError(err)
		require.NotNil(repo)

		name := "test-dup-name"
		_, prj := iam.TestScopes(t, iamRepo)
		catalog := TestCatalogs(t, conn, prj.PublicId, 1)[0]
		hs := TestHosts(t, conn, catalog.PublicId, 2)

		hA, hB := hs[0], hs[1]

		hA.Name = name
		got1, gotCount1, err := repo.UpdateHost(ctx, prj.GetPublicId(), hA, 1, []string{"name"})
		assert.NoError(err)
		require.NotNil(got1)
		assert.Equal(name, got1.Name)
		assert.Equal(1, gotCount1, "row count")
		assert.NoError(db.TestVerifyOplog(t, rw, hA.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))

		hB.Name = name
		got2, gotCount2, err := repo.UpdateHost(ctx, prj.GetPublicId(), hB, 1, []string{"name"})
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "want err code: %v got err: %v", errors.NotUnique, err)
		assert.Nil(got2)
		assert.Equal(db.NoRowsAffected, gotCount2, "row count")
		err = db.TestVerifyOplog(t, rw, hB.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
		assert.Error(err)
		assert.True(errors.IsNotFoundError(err))
	})

	t.Run("valid-duplicate-names-diff-Catalogs", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(ctx, rw, rw, kms)
		assert.NoError(err)
		require.NotNil(repo)

		_, prj := iam.TestScopes(t, iamRepo)
		catalogs := TestCatalogs(t, conn, prj.PublicId, 2)

		catalogA, catalogB := catalogs[0], catalogs[1]

		in := &Host{
			Host: &store.Host{
				Name:    "test-name-repo",
				Address: "127.0.0.1",
			},
		}
		in2 := in.clone()

		in.CatalogId = catalogA.PublicId
		got, err := repo.CreateHost(ctx, prj.GetPublicId(), in)
		assert.NoError(err)
		require.NotNil(got)
		assertPublicId(t, globals.StaticHostPrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)

		in2.CatalogId = catalogB.PublicId
		in2.Name = "first-name"
		got2, err := repo.CreateHost(ctx, prj.GetPublicId(), in2)
		assert.NoError(err)
		require.NotNil(got2)
		got2.Name = got.Name
		got3, gotCount3, err := repo.UpdateHost(ctx, prj.GetPublicId(), got2, 1, []string{"name"})
		assert.NoError(err)
		require.NotNil(got3)
		assert.NotSame(got2, got3)
		assert.Equal(got.Name, got3.Name)
		assert.Equal(got2.Description, got3.Description)
		assert.Equal(1, gotCount3, "row count")
		assert.NoError(db.TestVerifyOplog(t, rw, got2.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
	})

	t.Run("change-project-id", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(ctx, rw, rw, kms)
		assert.NoError(err)
		require.NotNil(repo)

		_, prj := iam.TestScopes(t, iamRepo)
		catalogs := TestCatalogs(t, conn, prj.PublicId, 2)

		catalogA, catalogB := catalogs[0], catalogs[1]

		hA := TestHosts(t, conn, catalogA.PublicId, 1)[0]
		hB := TestHosts(t, conn, catalogB.PublicId, 1)[0]

		assert.NotEqual(hA.CatalogId, hB.CatalogId)
		orig := hA.clone()

		hA.CatalogId = hB.CatalogId
		assert.Equal(hA.CatalogId, hB.CatalogId)

		got1, gotCount1, err := repo.UpdateHost(context.Background(), prj.GetPublicId(), hA, 1, []string{"name"})

		assert.NoError(err)
		require.NotNil(got1)
		assert.Equal(orig.CatalogId, got1.CatalogId)
		assert.Equal(1, gotCount1, "row count")
		assert.NoError(db.TestVerifyOplog(t, rw, hA.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
	})
}

func TestRepository_LookupHost(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	_, prj := iam.TestScopes(t, iamRepo)
	catalog := TestCatalogs(t, conn, prj.PublicId, 1)[0]
	host := TestHosts(t, conn, catalog.PublicId, 1)[0]

	hostId, err := newHostId(ctx)
	require.NoError(t, err)
	tests := []struct {
		name      string
		in        string
		want      *Host
		wantIsErr errors.Code
	}{
		{
			name:      "with-no-public-id",
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "with-non-existing-host-id",
			in:   hostId,
		},
		{
			name: "with-existing-host-id",
			in:   host.PublicId,
			want: host,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.LookupHost(ctx, tt.in)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			assert.EqualValues(tt.want, got)
		})
	}
}

func TestRepository_LookupHost_HostSets(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	_, prj := iam.TestScopes(t, iamRepo)
	catalog := TestCatalogs(t, conn, prj.PublicId, 1)[0]
	hosts := TestHosts(t, conn, catalog.PublicId, 3)
	hostA, hostB, hostC := hosts[0], hosts[1], hosts[2]
	setB := TestSets(t, conn, catalog.PublicId, 1)[0]
	setsC := TestSets(t, conn, catalog.PublicId, 5)
	TestSetMembers(t, conn, setB.PublicId, []*Host{hostB})
	hostB.SetIds = []string{setB.PublicId}
	for _, s := range setsC {
		hostC.SetIds = append(hostC.SetIds, s.PublicId)
		TestSetMembers(t, conn, s.PublicId, []*Host{hostC})
	}
	sort.Slice(hostC.SetIds, func(i, j int) bool {
		return hostC.SetIds[i] < hostC.SetIds[j]
	})

	tests := []struct {
		name      string
		in        string
		want      *Host
		wantIsErr errors.Code
	}{
		{
			name: "with-zero-hostsets",
			in:   hostA.PublicId,
			want: hostA,
		},
		{
			name: "with-one-hostset",
			in:   hostB.PublicId,
			want: hostB,
		},
		{
			name: "with-many-hostsets",
			in:   hostC.PublicId,
			want: hostC,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.LookupHost(ctx, tt.in)
			require.NoError(err)
			assert.Empty(
				cmp.Diff(
					tt.want,
					got,
					cmpopts.IgnoreUnexported(Host{}, store.Host{}),
					cmpopts.IgnoreTypes(&timestamp.Timestamp{}),
				),
			)
		})
	}
}

func TestRepository_ListHosts(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	_, prj := iam.TestScopes(t, iamRepo)
	catalogs := TestCatalogs(t, conn, prj.PublicId, 2)
	catalogA, catalogB := catalogs[0], catalogs[1]

	hosts := TestHosts(t, conn, catalogA.PublicId, 3)

	tests := []struct {
		name      string
		in        string
		opts      []Option
		want      []*Host
		wantIsErr errors.Code
	}{
		{
			name:      "with-no-catalog-id",
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "Catalog-with-no-hosts",
			in:   catalogB.PublicId,
			want: []*Host{},
		},
		{
			name: "Catalog-with-hosts",
			in:   catalogA.PublicId,
			want: hosts,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)
			got, ttime, err := repo.listHosts(ctx, tt.in, tt.opts...)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			opts := []cmp.Option{
				cmpopts.SortSlices(func(x, y *Host) bool { return x.PublicId < y.PublicId }),
				protocmp.Transform(),
			}
			assert.Empty(cmp.Diff(tt.want, got, opts...))
			// Transaction timestamp should be within ~10 seconds of now
			assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
			assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		})
	}
}

func TestRepository_ListHosts_HostSets(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iamRepo)

	// testing for full and empty hostset associations
	catalogs := TestCatalogs(t, conn, prj.PublicId, 3)
	catalogA, catalogB, catalogC := catalogs[0], catalogs[1], catalogs[2]
	hostsA := TestHosts(t, conn, catalogA.PublicId, 3)
	setA := TestSets(t, conn, catalogA.PublicId, 1)[0]
	TestSetMembers(t, conn, setA.PublicId, hostsA)
	for _, h := range hostsA {
		h.SetIds = []string{setA.PublicId}
	}
	hostsB := TestHosts(t, conn, catalogB.PublicId, 3)

	// testing for mixed hosts with individual hostsets and empty hostsets
	hostsC := TestHosts(t, conn, catalogC.PublicId, 5)
	hostsC0 := TestHosts(t, conn, catalogC.PublicId, 2)
	setC := TestSets(t, conn, catalogC.PublicId, 5)
	for i, h := range hostsC {
		h.SetIds = []string{setC[i].PublicId}
		TestSetMembers(t, conn, setC[i].PublicId, []*Host{hostsC[i]})
	}
	hostsC = append(hostsC, hostsC0...)

	tests := []struct {
		name string
		in   string
		want []*Host
	}{
		{
			name: "with-hostsets",
			in:   catalogA.PublicId,
			want: hostsA,
		},
		{
			name: "empty-hostsets",
			in:   catalogB.PublicId,
			want: hostsB,
		},
		{
			name: "mixed-hostsets",
			in:   catalogC.PublicId,
			want: hostsC,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)
			got, ttime, err := repo.listHosts(ctx, tt.in)
			require.NoError(err)
			assert.Empty(
				cmp.Diff(
					tt.want,
					got,
					cmpopts.IgnoreUnexported(Host{}, store.Host{}),
					cmpopts.IgnoreTypes(&timestamp.Timestamp{}),
					cmpopts.SortSlices(func(x, y *Host) bool {
						return x.GetPublicId() < y.GetPublicId()
					}),
				),
			)
			// Transaction timestamp should be within ~10 seconds of now
			assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
			assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		})
	}
}

func TestRepository_ListHosts_Limits(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	_, prj := iam.TestScopes(t, iamRepo)
	catalog := TestCatalogs(t, conn, prj.PublicId, 1)[0]
	count := 10
	hosts := TestHosts(t, conn, catalog.PublicId, count)

	tests := []struct {
		name     string
		repoOpts []Option
		listOpts []Option
		wantLen  int
	}{
		{
			name:    "With no limits",
			wantLen: count,
		},
		{
			name:     "With repo limit",
			repoOpts: []Option{WithLimit(3)},
			wantLen:  3,
		},
		{
			name:     "With List limit",
			listOpts: []Option{WithLimit(3)},
			wantLen:  3,
		},
		{
			name:     "With repo smaller than list limit",
			repoOpts: []Option{WithLimit(2)},
			listOpts: []Option{WithLimit(6)},
			wantLen:  6,
		},
		{
			name:     "With repo larger than list limit",
			repoOpts: []Option{WithLimit(6)},
			listOpts: []Option{WithLimit(2)},
			wantLen:  2,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kms, tt.repoOpts...)
			assert.NoError(err)
			require.NotNil(repo)
			got, ttime, err := repo.listHosts(ctx, hosts[0].CatalogId, tt.listOpts...)
			require.NoError(err)
			assert.Len(got, tt.wantLen)
			// Transaction timestamp should be within ~10 seconds of now
			assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
			assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		})
	}
}

func Test_listDeletedHostIds(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj1 := iam.TestScopes(t, iamRepo)
	catalog := TestCatalogs(t, conn, proj1.GetPublicId(), 1)[0]

	rw := db.New(conn)
	repo, err := NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)

	// Expect no entries at the start
	deletedIds, ttime, err := repo.listDeletedHostIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(t, err)
	require.Empty(t, deletedIds)
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))

	// Delete a host
	h := TestHosts(t, conn, catalog.GetPublicId(), 1)[0]
	_, err = repo.DeleteHost(ctx, proj1.GetPublicId(), h.GetPublicId())
	require.NoError(t, err)

	// Expect a single entry
	deletedIds, ttime, err = repo.listDeletedHostIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(t, err)
	require.Equal(t, []string{h.GetPublicId()}, deletedIds)
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))

	// Try again with the time set to now, expect no entries
	deletedIds, ttime, err = repo.listDeletedHostIds(ctx, time.Now())
	require.NoError(t, err)
	require.Empty(t, deletedIds)
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
}

func Test_estimatedHostCount(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(t, err)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj1 := iam.TestScopes(t, iamRepo)
	catalog := TestCatalogs(t, conn, proj1.GetPublicId(), 1)[0]

	rw := db.New(conn)
	repo, err := NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)

	// Check total entries at start, expect 0
	numItems, err := repo.estimatedHostCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, numItems)

	// Create a host, expect 1 entries
	h := TestHosts(t, conn, catalog.GetPublicId(), 1)[0]
	// Run analyze to update estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)
	numItems, err = repo.estimatedHostCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, numItems)

	// Delete the host, expect 0 again
	_, err = repo.DeleteHost(ctx, proj1.GetPublicId(), h.GetPublicId())
	require.NoError(t, err)
	// Run analyze to update estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)
	numItems, err = repo.estimatedHostCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, numItems)
}

func TestRepository_ListHosts_Pagination(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj1 := iam.TestScopes(t, iamRepo)
	catalog := TestCatalogs(t, conn, proj1.GetPublicId(), 1)[0]

	total := 5
	TestHosts(t, conn, catalog.GetPublicId(), total)

	rw := db.New(conn)
	repo, err := NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)

	t.Run("no-options", func(t *testing.T) {
		got, ttime, err := repo.listHosts(ctx, catalog.GetPublicId())
		require.NoError(t, err)
		assert.Equal(t, total, len(got))
		assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
		assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
	})

	t.Run("withStartPageAfter", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		page1, ttime, err := repo.listHosts(
			ctx,
			catalog.GetPublicId(),
			WithLimit(2),
		)
		require.NoError(err)
		require.Len(page1, 2)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		page2, ttime, err := repo.listHosts(
			ctx,
			catalog.GetPublicId(),
			WithLimit(2),
			WithStartPageAfterItem(page1[1]),
		)
		require.NoError(err)
		require.Len(page2, 2)
		for _, item := range page1 {
			assert.NotEqual(item.GetPublicId(), page2[0].GetPublicId())
			assert.NotEqual(item.GetPublicId(), page2[1].GetPublicId())
		}
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		page3, ttime, err := repo.listHosts(
			ctx,
			catalog.GetPublicId(),
			WithLimit(2),
			WithStartPageAfterItem(page2[1]),
		)
		require.NoError(err)
		require.Len(page3, 1)
		for _, item := range page2 {
			assert.NotEqual(item.GetPublicId(), page3[0].GetPublicId())
		}
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		page4, ttime, err := repo.listHosts(
			ctx,
			catalog.GetPublicId(),
			WithLimit(2),
			WithStartPageAfterItem(page3[0]),
		)
		require.NoError(err)
		require.Empty(page4, 2)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
	})
}

func TestRepository_DeleteHost(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	_, prj := iam.TestScopes(t, iamRepo)
	catalog := TestCatalogs(t, conn, prj.PublicId, 1)[0]
	host := TestHosts(t, conn, catalog.PublicId, 1)[0]

	newHostId, err := newHostId(ctx)
	require.NoError(t, err)
	tests := []struct {
		name      string
		in        string
		want      int
		wantIsErr errors.Code
	}{
		{
			name:      "With no public id",
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "With non existing host id",
			in:   newHostId,
			want: 0,
		},
		{
			name: "With existing host id",
			in:   host.PublicId,
			want: 1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.DeleteHost(ctx, catalog.ProjectId, tt.in)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Zero(got)
				return
			}
			require.NoError(err)
			assert.EqualValues(tt.want, got)
		})
	}
}
