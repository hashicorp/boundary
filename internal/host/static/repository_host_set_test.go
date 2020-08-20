package static

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	dbassert "github.com/hashicorp/boundary/internal/db/assert"
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

func TestRepository_UpdateHostSet(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

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

	var tests = []struct {
		name      string
		orig      *HostSet
		chgFn     func(*HostSet) *HostSet
		masks     []string
		want      *HostSet
		wantCount int
		wantIsErr error
	}{
		{
			name: "nil-host-set",
			orig: &HostSet{
				HostSet: &store.HostSet{},
			},
			chgFn:     makeNil(),
			masks:     []string{"Name", "Description"},
			wantIsErr: db.ErrNilParameter,
		},
		{
			name: "nil-embedded-host-set",
			orig: &HostSet{
				HostSet: &store.HostSet{},
			},
			chgFn:     makeEmbeddedNil(),
			masks:     []string{"Name", "Description"},
			wantIsErr: db.ErrNilParameter,
		},
		{
			name: "no-public-id",
			orig: &HostSet{
				HostSet: &store.HostSet{},
			},
			chgFn:     deletePublicId(),
			masks:     []string{"Name", "Description"},
			wantIsErr: db.ErrInvalidParameter,
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
			wantIsErr: db.ErrRecordNotFound,
		},
		{
			name: "empty-field-mask",
			orig: &HostSet{
				HostSet: &store.HostSet{
					Name: "test-name-repo",
				},
			},
			chgFn:     changeName("test-update-name-repo"),
			wantIsErr: db.ErrEmptyFieldMask,
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
			wantIsErr: db.ErrInvalidFieldMask,
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
			wantIsErr: db.ErrInvalidFieldMask,
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
			repo, err := NewRepository(rw, rw, wrapper)
			assert.NoError(err)
			require.NotNil(repo)

			_, prj := iam.TestScopes(t, conn)
			catalog := testCatalogs(t, conn, prj.PublicId, 1)[0]

			tt.orig.CatalogId = catalog.PublicId
			orig, err := repo.CreateSet(context.Background(), tt.orig)
			assert.NoError(err)
			require.NotNil(orig)

			if tt.chgFn != nil {
				orig = tt.chgFn(orig)
			}
			got, gotCount, err := repo.UpdateSet(context.Background(), orig, 1, tt.masks)
			if tt.wantIsErr != nil {
				assert.Truef(errors.Is(err, tt.wantIsErr), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Equal(tt.wantCount, gotCount, "row count")
				assert.Nil(got)
				return
			}
			assert.NoError(err)
			assert.Empty(tt.orig.PublicId)
			require.NotNil(got)
			assertPublicId(t, HostSetPrefix, got.PublicId)
			assert.Equal(tt.wantCount, gotCount, "row count")
			assert.NotSame(tt.orig, got)
			assert.Equal(tt.orig.CatalogId, got.CatalogId)
			dbassert := dbassert.New(t, rw)
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
		})
	}

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(rw, rw, wrapper)
		assert.NoError(err)
		require.NotNil(repo)

		name := "test-dup-name"
		_, prj := iam.TestScopes(t, conn)
		catalog := testCatalogs(t, conn, prj.PublicId, 1)[0]
		ss := testSets(t, conn, catalog.PublicId, 2)

		sA, sB := ss[0], ss[1]

		sA.Name = name
		got1, gotCount1, err := repo.UpdateSet(context.Background(), sA, 1, []string{"name"})
		assert.NoError(err)
		require.NotNil(got1)
		assert.Equal(name, got1.Name)
		assert.Equal(1, gotCount1, "row count")
		assert.NoError(db.TestVerifyOplog(t, rw, sA.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))

		sB.Name = name
		got2, gotCount2, err := repo.UpdateSet(context.Background(), sB, 1, []string{"name"})
		assert.Truef(errors.Is(err, db.ErrNotUnique), "want err: %v got: %v", db.ErrNotUnique, err)
		assert.Nil(got2)
		assert.Equal(db.NoRowsAffected, gotCount2, "row count")
		err = db.TestVerifyOplog(t, rw, sB.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
		assert.Error(err)
		assert.True(errors.Is(db.ErrRecordNotFound, err))
	})

	t.Run("valid-duplicate-names-diff-Catalogs", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(rw, rw, wrapper)
		assert.NoError(err)
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
		assert.NoError(err)
		require.NotNil(got)
		assertPublicId(t, HostSetPrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)

		in2.CatalogId = catalogB.PublicId
		in2.Name = "first-name"
		got2, err := repo.CreateSet(context.Background(), in2)
		assert.NoError(err)
		require.NotNil(got2)
		got2.Name = got.Name
		got3, gotCount3, err := repo.UpdateSet(context.Background(), got2, 1, []string{"name"})
		assert.NoError(err)
		require.NotNil(got3)
		assert.NotSame(got2, got3)
		assert.Equal(got.Name, got3.Name)
		assert.Equal(got2.Description, got3.Description)
		assert.Equal(1, gotCount3, "row count")
		assert.NoError(db.TestVerifyOplog(t, rw, got2.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
	})

	t.Run("change-scope-id", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(rw, rw, wrapper)
		assert.NoError(err)
		require.NotNil(repo)

		_, prj := iam.TestScopes(t, conn)
		catalogs := testCatalogs(t, conn, prj.PublicId, 2)

		catalogA, catalogB := catalogs[0], catalogs[1]

		sA := testSets(t, conn, catalogA.PublicId, 1)[0]
		sB := testSets(t, conn, catalogB.PublicId, 1)[0]

		assert.NotEqual(sA.CatalogId, sB.CatalogId)
		orig := sA.clone()

		sA.CatalogId = sB.CatalogId
		assert.Equal(sA.CatalogId, sB.CatalogId)

		got1, gotCount1, err := repo.UpdateSet(context.Background(), sA, 1, []string{"name"})

		assert.NoError(err)
		require.NotNil(got1)
		assert.Equal(orig.CatalogId, got1.CatalogId)
		assert.Equal(1, gotCount1, "row count")
		assert.NoError(db.TestVerifyOplog(t, rw, sA.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
	})
}
