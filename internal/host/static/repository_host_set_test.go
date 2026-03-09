// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package static

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	dbassert "github.com/hashicorp/boundary/internal/db/assert"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/static/store"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestRepository_CreateSet(t *testing.T) {
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
		in        *HostSet
		opts      []Option
		want      *HostSet
		wantIsErr errors.Code
	}{
		{
			name:      "nil-HostSet",
			wantIsErr: errors.InvalidParameter,
		},
		{
			name:      "nil-embedded-HostSet",
			in:        &HostSet{},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "invalid-no-catalog-id",
			in: &HostSet{
				HostSet: &store.HostSet{},
			},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "invalid-public-id-set",
			in: &HostSet{
				HostSet: &store.HostSet{
					CatalogId: catalog.PublicId,
					PublicId:  "abcd_OOOOOOOOOO",
				},
			},
			wantIsErr: errors.InvalidParameter,
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
			repo, err := NewRepository(ctx, rw, rw, kms)
			require.NoError(err)
			require.NotNil(repo)
			got, err := repo.CreateSet(ctx, prj.GetPublicId(), tt.in, tt.opts...)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			assert.Empty(tt.in.PublicId)
			require.NotNil(got)
			assertPublicId(t, globals.StaticHostSetPrefix, got.PublicId)
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

		in := &HostSet{
			HostSet: &store.HostSet{
				CatalogId: catalog.PublicId,
				Name:      "test-name-repo",
			},
		}

		got, err := repo.CreateSet(ctx, prj.GetPublicId(), in)
		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, globals.StaticHostSetPrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		got2, err := repo.CreateSet(ctx, prj.GetPublicId(), in)
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

		in := &HostSet{
			HostSet: &store.HostSet{
				Name: "test-name-repo",
			},
		}
		in2 := in.clone()

		in.CatalogId = catalogA.PublicId
		got, err := repo.CreateSet(ctx, prj.GetPublicId(), in)
		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, globals.StaticHostSetPrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		in2.CatalogId = catalogB.PublicId
		got2, err := repo.CreateSet(ctx, prj.GetPublicId(), in2)
		require.NoError(err)
		require.NotNil(got2)
		assertPublicId(t, globals.StaticHostSetPrefix, got2.PublicId)
		assert.NotSame(in2, got2)
		assert.Equal(in2.Name, got2.Name)
		assert.Equal(in2.Description, got2.Description)
		assert.Equal(got2.CreateTime, got2.UpdateTime)
	})
}

func TestRepository_UpdateSet(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	changeName := func(n string) func(*HostSet) *HostSet {
		return func(s *HostSet) *HostSet {
			s.Name = n
			return s
		}
	}

	changeDescription := func(d string) func(*HostSet) *HostSet {
		return func(s *HostSet) *HostSet {
			s.Description = d
			return s
		}
	}

	makeNil := func() func(*HostSet) *HostSet {
		return func(s *HostSet) *HostSet {
			return nil
		}
	}

	makeEmbeddedNil := func() func(*HostSet) *HostSet {
		return func(s *HostSet) *HostSet {
			return &HostSet{}
		}
	}

	deletePublicId := func() func(*HostSet) *HostSet {
		return func(s *HostSet) *HostSet {
			s.PublicId = ""
			return s
		}
	}

	nonExistentPublicId := func() func(*HostSet) *HostSet {
		return func(s *HostSet) *HostSet {
			s.PublicId = "abcd_OOOOOOOOOO"
			return s
		}
	}

	combine := func(fns ...func(s *HostSet) *HostSet) func(*HostSet) *HostSet {
		return func(s *HostSet) *HostSet {
			for _, fn := range fns {
				s = fn(s)
			}
			return s
		}
	}

	tests := []struct {
		name      string
		orig      *HostSet
		chgFn     func(*HostSet) *HostSet
		masks     []string
		want      *HostSet
		wantCount int
		wantIsErr errors.Code
	}{
		{
			name: "nil-host-set",
			orig: &HostSet{
				HostSet: &store.HostSet{},
			},
			chgFn:     makeNil(),
			masks:     []string{"Name", "Description"},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "nil-embedded-host-set",
			orig: &HostSet{
				HostSet: &store.HostSet{},
			},
			chgFn:     makeEmbeddedNil(),
			masks:     []string{"Name", "Description"},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "no-public-id",
			orig: &HostSet{
				HostSet: &store.HostSet{},
			},
			chgFn:     deletePublicId(),
			masks:     []string{"Name", "Description"},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "updating-non-existent-host-set",
			orig: &HostSet{
				HostSet: &store.HostSet{
					Name: "test-name-repo",
				},
			},
			chgFn:     combine(nonExistentPublicId(), changeName("test-update-name-repo")),
			masks:     []string{"Name"},
			wantIsErr: errors.RecordNotFound,
		},
		{
			name: "empty-field-mask",
			orig: &HostSet{
				HostSet: &store.HostSet{
					Name: "test-name-repo",
				},
			},
			chgFn:     changeName("test-update-name-repo"),
			wantIsErr: errors.EmptyFieldMask,
		},
		{
			name: "read-only-fields-in-field-mask",
			orig: &HostSet{
				HostSet: &store.HostSet{
					Name: "test-name-repo",
				},
			},
			chgFn:     changeName("test-update-name-repo"),
			masks:     []string{"PublicId", "CreateTime", "UpdateTime", "CatalogId"},
			wantIsErr: errors.InvalidFieldMask,
		},
		{
			name: "unknown-field-in-field-mask",
			orig: &HostSet{
				HostSet: &store.HostSet{
					Name: "test-name-repo",
				},
			},
			chgFn:     changeName("test-update-name-repo"),
			masks:     []string{"Bilbo"},
			wantIsErr: errors.InvalidFieldMask,
		},
		{
			name: "change-name",
			orig: &HostSet{
				HostSet: &store.HostSet{
					Name: "test-name-repo",
				},
			},
			chgFn: changeName("test-update-name-repo"),
			masks: []string{"Name"},
			want: &HostSet{
				HostSet: &store.HostSet{
					Name: "test-update-name-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-description",
			orig: &HostSet{
				HostSet: &store.HostSet{
					Description: "test-description-repo",
				},
			},
			chgFn: changeDescription("test-update-description-repo"),
			masks: []string{"Description"},
			want: &HostSet{
				HostSet: &store.HostSet{
					Description: "test-update-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-name-and-description",
			orig: &HostSet{
				HostSet: &store.HostSet{
					Name:        "test-name-repo",
					Description: "test-description-repo",
				},
			},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("test-update-name-repo")),
			masks: []string{"Name", "Description"},
			want: &HostSet{
				HostSet: &store.HostSet{
					Name:        "test-update-name-repo",
					Description: "test-update-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "delete-name",
			orig: &HostSet{
				HostSet: &store.HostSet{
					Name:        "test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{"Name"},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("")),
			want: &HostSet{
				HostSet: &store.HostSet{
					Description: "test-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "delete-description",
			orig: &HostSet{
				HostSet: &store.HostSet{
					Name:        "test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{"Description"},
			chgFn: combine(changeDescription(""), changeName("test-update-name-repo")),
			want: &HostSet{
				HostSet: &store.HostSet{
					Name: "test-name-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-name",
			orig: &HostSet{
				HostSet: &store.HostSet{
					Name:        "test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{"Description"},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("")),
			want: &HostSet{
				HostSet: &store.HostSet{
					Name:        "test-name-repo",
					Description: "test-update-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-description",
			orig: &HostSet{
				HostSet: &store.HostSet{
					Name:        "test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{"Name"},
			chgFn: combine(changeDescription(""), changeName("test-update-name-repo")),
			want: &HostSet{
				HostSet: &store.HostSet{
					Name:        "test-update-name-repo",
					Description: "test-description-repo",
				},
			},
			wantCount: 1,
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
			hosts := TestHosts(t, conn, catalog.PublicId, 5)

			tt.orig.CatalogId = catalog.PublicId
			orig, err := repo.CreateSet(ctx, prj.GetPublicId(), tt.orig)
			assert.NoError(err)
			require.NotNil(orig)
			TestSetMembers(t, conn, orig.PublicId, hosts)

			if tt.chgFn != nil {
				orig = tt.chgFn(orig)
			}
			got, gotHosts, gotCount, err := repo.UpdateSet(ctx, prj.GetPublicId(), orig, 1, tt.masks)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Equal(tt.wantCount, gotCount, "row count")
				assert.Nil(got)
				return
			}
			assert.NoError(err)
			assert.Empty(tt.orig.PublicId)
			require.NotNil(got)
			assertPublicId(t, globals.StaticHostSetPrefix, got.PublicId)
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
			assert.Equal(tt.want.Name, got.Name)
			if tt.want.Description == "" {
				dbassert.IsNull(got, "description")
				return
			}
			assert.Equal(tt.want.Description, got.Description)
			if tt.wantCount > 0 {
				assert.NoError(db.TestVerifyOplog(t, rw, got.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
			}
			require.Len(gotHosts, len(hosts))
			opts := []cmp.Option{
				cmpopts.SortSlices(func(x, y *Host) bool { return x.PublicId < y.PublicId }),
				protocmp.Transform(),
			}
			assert.Empty(cmp.Diff(hosts, gotHosts, opts...))
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
		ss := TestSets(t, conn, catalog.PublicId, 2)

		sA, sB := ss[0], ss[1]

		sA.Name = name
		got1, gotHosts1, gotCount1, err := repo.UpdateSet(ctx, prj.GetPublicId(), sA, 1, []string{"name"})
		assert.NoError(err)
		require.NotNil(got1)
		assert.Equal(name, got1.Name)
		assert.Equal(1, gotCount1, "row count")
		assert.NoError(db.TestVerifyOplog(t, rw, sA.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
		assert.Empty(gotHosts1)

		sB.Name = name
		got2, gotHosts, gotCount2, err := repo.UpdateSet(ctx, prj.GetPublicId(), sB, 1, []string{"name"})
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "want err code: %v got err: %v", errors.NotUnique, err)
		assert.Nil(got2)
		assert.Equal(db.NoRowsAffected, gotCount2, "row count")
		err = db.TestVerifyOplog(t, rw, sB.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
		assert.Error(err)
		assert.True(errors.IsNotFoundError(err))
		assert.Empty(gotHosts)
	})

	t.Run("valid-duplicate-names-diff-Catalogs", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(ctx, rw, rw, kms)
		assert.NoError(err)
		require.NotNil(repo)

		_, prj := iam.TestScopes(t, iamRepo)
		catalogs := TestCatalogs(t, conn, prj.PublicId, 2)

		catalogA, catalogB := catalogs[0], catalogs[1]

		in := &HostSet{
			HostSet: &store.HostSet{
				Name: "test-name-repo",
			},
		}
		in2 := in.clone()

		in.CatalogId = catalogA.PublicId
		got, err := repo.CreateSet(ctx, prj.GetPublicId(), in)
		assert.NoError(err)
		require.NotNil(got)
		assertPublicId(t, globals.StaticHostSetPrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)

		in2.CatalogId = catalogB.PublicId
		in2.Name = "first-name"
		got2, err := repo.CreateSet(ctx, prj.GetPublicId(), in2)
		assert.NoError(err)
		require.NotNil(got2)
		got2.Name = got.Name
		got3, gotHosts3, gotCount3, err := repo.UpdateSet(ctx, prj.GetPublicId(), got2, 1, []string{"name"})
		assert.NoError(err)
		require.NotNil(got3)
		assert.NotSame(got2, got3)
		assert.Equal(got.Name, got3.Name)
		assert.Equal(got2.Description, got3.Description)
		assert.Equal(1, gotCount3, "row count")
		assert.NoError(db.TestVerifyOplog(t, rw, got2.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
		assert.Empty(gotHosts3)
	})

	t.Run("change-project-id", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(ctx, rw, rw, kms)
		assert.NoError(err)
		require.NotNil(repo)

		_, prj := iam.TestScopes(t, iamRepo)
		catalogs := TestCatalogs(t, conn, prj.PublicId, 2)

		catalogA, catalogB := catalogs[0], catalogs[1]

		sA := TestSets(t, conn, catalogA.PublicId, 1)[0]
		sB := TestSets(t, conn, catalogB.PublicId, 1)[0]

		assert.NotEqual(sA.CatalogId, sB.CatalogId)
		orig := sA.clone()

		sA.CatalogId = sB.CatalogId
		assert.Equal(sA.CatalogId, sB.CatalogId)

		got1, gotHosts1, gotCount1, err := repo.UpdateSet(ctx, prj.GetPublicId(), sA, 1, []string{"name"})

		assert.NoError(err)
		require.NotNil(got1)
		assert.Equal(orig.CatalogId, got1.CatalogId)
		assert.Equal(1, gotCount1, "row count")
		assert.NoError(db.TestVerifyOplog(t, rw, sA.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
		assert.Empty(gotHosts1)
	})
}

func TestRepository_UpdateSet_Limits(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	_, prj := iam.TestScopes(t, iamRepo)
	catalog := TestCatalogs(t, conn, prj.PublicId, 1)[0]
	hostSet := TestSets(t, conn, catalog.PublicId, 1)[0]
	count := 10
	hosts := TestHosts(t, conn, catalog.PublicId, count)
	TestSetMembers(t, conn, hostSet.PublicId, hosts)

	tests := []struct {
		name       string
		repoOpts   []Option
		updateOpts []Option
		wantLen    int
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
			name:     "With negative repo limit",
			repoOpts: []Option{WithLimit(-1)},
			wantLen:  count,
		},
		{
			name:       "With List limit",
			updateOpts: []Option{WithLimit(3)},
			wantLen:    3,
		},
		{
			name:       "With negative List limit",
			updateOpts: []Option{WithLimit(-1)},
			wantLen:    count,
		},
		{
			name:       "With repo smaller than list limit",
			repoOpts:   []Option{WithLimit(2)},
			updateOpts: []Option{WithLimit(6)},
			wantLen:    6,
		},
		{
			name:       "With repo larger than list limit",
			repoOpts:   []Option{WithLimit(6)},
			updateOpts: []Option{WithLimit(2)},
			wantLen:    2,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kms, tt.repoOpts...)
			assert.NoError(err)
			require.NotNil(repo)
			hs := hostSet.clone()
			hs.Description = tt.name
			got, gotHosts, _, err := repo.UpdateSet(ctx, prj.PublicId, hs, hs.Version, []string{"Description"}, tt.updateOpts...)
			require.NoError(err)
			require.NotNil(got)
			assert.Len(gotHosts, tt.wantLen)
			require.Greater(got.Version, hs.Version)
			hostSet = got
		})
	}
}

func TestRepository_LookupSet(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iamRepo)

	catalog := TestCatalogs(t, conn, prj.PublicId, 1)[0]
	hostSet := TestSets(t, conn, catalog.PublicId, 1)[0]
	hosts := TestHosts(t, conn, catalog.PublicId, 1)
	TestSetMembers(t, conn, hostSet.PublicId, hosts)

	emptyHostSet := TestSets(t, conn, catalog.PublicId, 1)[0]

	hostSetId, err := newHostSetId(ctx)
	require.NoError(t, err)

	tests := []struct {
		name      string
		in        string
		want      *HostSet
		wantHosts []*Host
		wantIsErr errors.Code
	}{
		{
			name:      "with-no-public-id",
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "with-non-existing-host-set-id",
			in:   hostSetId,
		},
		{
			name:      "with-existing-host-set-id",
			in:        hostSet.PublicId,
			want:      hostSet,
			wantHosts: hosts,
		},
		{
			name:      "with-existing-host-set-id-empty-hosts",
			in:        emptyHostSet.PublicId,
			want:      emptyHostSet,
			wantHosts: nil,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)
			got, gotHosts, err := repo.LookupSet(ctx, tt.in)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			assert.EqualValues(tt.want, got)
			require.Len(gotHosts, len(tt.wantHosts))
			opts := []cmp.Option{
				cmpopts.SortSlices(func(x, y *Host) bool { return x.PublicId < y.PublicId }),
				protocmp.Transform(),
			}
			assert.Empty(cmp.Diff(tt.wantHosts, gotHosts, opts...))
		})
	}
}

func TestRepository_LookupSet_Limits(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	_, prj := iam.TestScopes(t, iamRepo)
	catalog := TestCatalogs(t, conn, prj.PublicId, 1)[0]
	hostSet := TestSets(t, conn, catalog.PublicId, 1)[0]
	count := 10
	hosts := TestHosts(t, conn, catalog.PublicId, count)
	TestSetMembers(t, conn, hostSet.PublicId, hosts)

	tests := []struct {
		name       string
		repoOpts   []Option
		lookupOpts []Option
		wantLen    int
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
			name:     "With negative repo limit",
			repoOpts: []Option{WithLimit(-1)},
			wantLen:  count,
		},
		{
			name:       "With List limit",
			lookupOpts: []Option{WithLimit(3)},
			wantLen:    3,
		},
		{
			name:       "With negative List limit",
			lookupOpts: []Option{WithLimit(-1)},
			wantLen:    count,
		},
		{
			name:       "With repo smaller than list limit",
			repoOpts:   []Option{WithLimit(2)},
			lookupOpts: []Option{WithLimit(6)},
			wantLen:    6,
		},
		{
			name:       "With repo larger than list limit",
			repoOpts:   []Option{WithLimit(6)},
			lookupOpts: []Option{WithLimit(2)},
			wantLen:    2,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kms, tt.repoOpts...)
			assert.NoError(err)
			require.NotNil(repo)
			got, gotHosts, err := repo.LookupSet(context.Background(), hostSet.PublicId, tt.lookupOpts...)
			require.NoError(err)
			require.NotNil(got)
			assert.Len(gotHosts, tt.wantLen)
		})
	}
}

func TestRepository_listSets(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	_, prj := iam.TestScopes(t, iamRepo)
	catalogs := TestCatalogs(t, conn, prj.PublicId, 2)
	catalogA, catalogB := catalogs[0], catalogs[1]

	hostSets := TestSets(t, conn, catalogA.PublicId, 3)

	tests := []struct {
		name      string
		in        string
		opts      []Option
		want      []*HostSet
		wantIsErr errors.Code
	}{
		{
			name:      "with-no-catalog-id",
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "Catalog-with-no-host-sets",
			in:   catalogB.PublicId,
			want: []*HostSet{},
		},
		{
			name: "Catalog-with-host-sets",
			in:   catalogA.PublicId,
			want: hostSets,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)
			got, ttime, err := repo.listSets(ctx, tt.in, tt.opts...)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			opts := []cmp.Option{
				cmpopts.SortSlices(func(x, y *HostSet) bool { return x.PublicId < y.PublicId }),
				protocmp.Transform(),
			}
			assert.Empty(cmp.Diff(tt.want, got, opts...))
			// Transaction timestamp should be within ~10 seconds of now
			assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
			assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		})
	}
}

func TestRepository_listSets_Limits(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	_, prj := iam.TestScopes(t, iamRepo)
	catalog := TestCatalogs(t, conn, prj.PublicId, 1)[0]
	count := 10
	hostSets := TestSets(t, conn, catalog.PublicId, count)

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
			name:     "With negative repo limit",
			repoOpts: []Option{WithLimit(-1)},
			wantLen:  count,
		},
		{
			name:     "With List limit",
			listOpts: []Option{WithLimit(3)},
			wantLen:  3,
		},
		{
			name:     "With negative List limit",
			listOpts: []Option{WithLimit(-1)},
			wantLen:  count,
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
			got, ttime, err := repo.listSets(ctx, hostSets[0].CatalogId, tt.listOpts...)
			require.NoError(err)
			assert.Len(got, tt.wantLen)
			// Transaction timestamp should be within ~10 seconds of now
			assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
			assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		})
	}
}

func Test_listDeletedSetIds(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iamRepo)
	catalog := TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]

	rw := db.New(conn)
	repo, err := NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)

	// Expect no entries at the start
	deletedIds, ttime, err := repo.listDeletedSetIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(t, err)
	require.Empty(t, deletedIds)
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))

	// Delete a set
	s := TestSets(t, conn, catalog.GetPublicId(), 1)[0]
	_, err = repo.DeleteSet(ctx, proj.GetPublicId(), s.GetPublicId())
	require.NoError(t, err)

	// Expect a single entry
	deletedIds, ttime, err = repo.listDeletedSetIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(t, err)
	require.Equal(t, []string{s.GetPublicId()}, deletedIds)
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))

	// Try again with the time set to now, expect no entries
	deletedIds, ttime, err = repo.listDeletedSetIds(ctx, time.Now())
	require.NoError(t, err)
	require.Empty(t, deletedIds)
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
}

func Test_estimatedHostSetCount(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(t, err)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iamRepo)
	catalog := TestCatalogs(t, conn, proj.GetPublicId(), 1)[0]

	rw := db.New(conn)
	repo, err := NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)

	// Check total entries at start, expect 0
	numItems, err := repo.estimatedSetCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, numItems)

	// Create a set, expect 1 entries
	s := TestSets(t, conn, catalog.GetPublicId(), 1)[0]
	// Run analyze to update estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)
	numItems, err = repo.estimatedSetCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, numItems)

	// Delete the set, expect 0 again
	_, err = repo.DeleteSet(ctx, proj.GetPublicId(), s.GetPublicId())
	require.NoError(t, err)
	// Run analyze to update estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)
	numItems, err = repo.estimatedSetCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, numItems)
}

func TestRepository_DeleteSet(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	_, prj := iam.TestScopes(t, iamRepo)
	catalog := TestCatalogs(t, conn, prj.PublicId, 1)[0]
	hostSet := TestSets(t, conn, catalog.PublicId, 1)[0]

	newHostSetId, err := newHostSetId(ctx)
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
			name: "With non existing host set id",
			in:   newHostSetId,
			want: 0,
		},
		{
			name: "With existing host set id",
			in:   hostSet.PublicId,
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
			got, err := repo.DeleteSet(ctx, prj.PublicId, tt.in)
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
