package static

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	dbassert "github.com/hashicorp/boundary/internal/db/assert"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/static/store"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_CreateCatalog(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	tests := []struct {
		name      string
		in        *HostCatalog
		opts      []Option
		want      *HostCatalog
		wantIsErr errors.Code
	}{
		{
			name:      "nil-catalog",
			wantIsErr: errors.InvalidParameter,
		},
		{
			name:      "nil-embedded-catalog",
			in:        &HostCatalog{},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "valid-no-options",
			in: &HostCatalog{
				HostCatalog: &store.HostCatalog{},
			},
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{},
			},
		},
		{
			name: "valid-with-name",
			in: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					Name: "test-name-repo",
				},
			},
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					Name: "test-name-repo",
				},
			},
		},
		{
			name: "valid-with-description",
			in: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					Description: ("test-description-repo"),
				},
			},
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					Description: ("test-description-repo"),
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			kms := kms.TestKms(t, conn, wrapper)
			repo, err := NewRepository(rw, rw, kms)
			assert.NoError(err)
			assert.NotNil(repo)
			_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
			if tt.in != nil && tt.in.HostCatalog != nil {
				tt.in.ScopeId = prj.GetPublicId()
				assert.Empty(tt.in.PublicId)
			}
			got, err := repo.CreateCatalog(context.Background(), tt.in, tt.opts...)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Nil(got)
				return
			}
			assert.NoError(err)
			assert.Empty(tt.in.PublicId)
			assert.NotNil(got)
			assertPublicId(t, "hcst", got.PublicId)
			assert.NotSame(tt.in, got)
			assert.Equal(tt.want.Name, got.Name)
			assert.Equal(tt.want.Description, got.Description)
			assert.Equal(got.CreateTime, got.UpdateTime)
		})
	}

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert := assert.New(t)
		kms := kms.TestKms(t, conn, wrapper)
		repo, err := NewRepository(rw, rw, kms)
		assert.NoError(err)
		assert.NotNil(repo)
		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		in := &HostCatalog{
			HostCatalog: &store.HostCatalog{
				ScopeId: prj.GetPublicId(),
				Name:    "test-name-repo",
			},
		}

		got, err := repo.CreateCatalog(context.Background(), in)
		assert.NoError(err)
		assert.NotNil(got)
		assertPublicId(t, "hcst", got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		got2, err := repo.CreateCatalog(context.Background(), in)
		assert.Truef(errors.Is(err, errors.ErrNotUnique), "want err: %v got: %v", errors.ErrNotUnique, err)
		assert.Nil(got2)
	})

	t.Run("valid-duplicate-names-diff-scopes", func(t *testing.T) {
		assert := assert.New(t)
		kms := kms.TestKms(t, conn, wrapper)
		repo, err := NewRepository(rw, rw, kms)
		assert.NoError(err)
		assert.NotNil(repo)
		org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		in := &HostCatalog{
			HostCatalog: &store.HostCatalog{
				Name: "test-name-repo",
			},
		}
		in2 := in.clone()

		in.ScopeId = prj.GetPublicId()
		got, err := repo.CreateCatalog(context.Background(), in)
		assert.NoError(err)
		assert.NotNil(got)
		assertPublicId(t, "hcst", got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		in2.ScopeId = org.GetPublicId()
		got2, err := repo.CreateCatalog(context.Background(), in2)
		assert.NoError(err)
		assert.NotNil(got2)
		assertPublicId(t, "hcst", got2.PublicId)
		assert.NotSame(in2, got2)
		assert.Equal(in2.Name, got2.Name)
		assert.Equal(in2.Description, got2.Description)
		assert.Equal(got2.CreateTime, got2.UpdateTime)
	})
}

func assertPublicId(t *testing.T, prefix, actual string) {
	t.Helper()
	assert.NotEmpty(t, actual)
	parts := strings.Split(actual, "_")
	assert.Equalf(t, 2, len(parts), "want one '_' in PublicId, got multiple in %q", actual)
	assert.Equalf(t, prefix, parts[0], "PublicId want prefix: %q, got: %q in %q", prefix, parts[0], actual)
}

func TestRepository_UpdateCatalog(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	changeName := func(s string) func(*HostCatalog) *HostCatalog {
		return func(c *HostCatalog) *HostCatalog {
			c.Name = s
			return c
		}
	}

	changeDescription := func(s string) func(*HostCatalog) *HostCatalog {
		return func(c *HostCatalog) *HostCatalog {
			c.Description = s
			return c
		}
	}

	makeNil := func() func(*HostCatalog) *HostCatalog {
		return func(c *HostCatalog) *HostCatalog {
			return nil
		}
	}

	makeEmbeddedNil := func() func(*HostCatalog) *HostCatalog {
		return func(c *HostCatalog) *HostCatalog {
			return &HostCatalog{}
		}
	}

	deletePublicId := func() func(*HostCatalog) *HostCatalog {
		return func(c *HostCatalog) *HostCatalog {
			c.PublicId = ""
			return c
		}
	}

	nonExistentPublicId := func() func(*HostCatalog) *HostCatalog {
		return func(c *HostCatalog) *HostCatalog {
			c.PublicId = "hcst_OOOOOOOOOO"
			return c
		}
	}

	combine := func(fns ...func(c *HostCatalog) *HostCatalog) func(*HostCatalog) *HostCatalog {
		return func(c *HostCatalog) *HostCatalog {
			for _, fn := range fns {
				c = fn(c)
			}
			return c
		}
	}

	tests := []struct {
		name      string
		orig      *HostCatalog
		chgFn     func(*HostCatalog) *HostCatalog
		masks     []string
		want      *HostCatalog
		wantCount int
		wantIsErr errors.Code
	}{
		{
			name: "nil-catalog",
			orig: &HostCatalog{
				HostCatalog: &store.HostCatalog{},
			},
			chgFn:     makeNil(),
			masks:     []string{"Name", "Description"},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "nil-embedded-catalog",
			orig: &HostCatalog{
				HostCatalog: &store.HostCatalog{},
			},
			chgFn:     makeEmbeddedNil(),
			masks:     []string{"Name", "Description"},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "no-public-id",
			orig: &HostCatalog{
				HostCatalog: &store.HostCatalog{},
			},
			chgFn:     deletePublicId(),
			masks:     []string{"Name", "Description"},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "updating-non-existent-catalog",
			orig: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					Name: "test-name-repo",
				},
			},
			chgFn:     combine(nonExistentPublicId(), changeName("test-update-name-repo")),
			masks:     []string{"Name"},
			wantIsErr: errors.RecordNotFound,
		},
		{
			name: "empty-field-mask",
			orig: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					Name: "test-name-repo",
				},
			},
			chgFn:     changeName("test-update-name-repo"),
			wantIsErr: errors.EmptyFieldMask,
		},
		{
			name: "read-only-fields-in-field-mask",
			orig: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					Name: "test-name-repo",
				},
			},
			chgFn:     changeName("test-update-name-repo"),
			masks:     []string{"PublicId", "CreateTime", "UpdateTime", "ScopeId"},
			wantIsErr: errors.InvalidFieldMask,
		},
		{
			name: "unknown-field-in-field-mask",
			orig: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					Name: "test-name-repo",
				},
			},
			chgFn:     changeName("test-update-name-repo"),
			masks:     []string{"Bilbo"},
			wantIsErr: errors.InvalidFieldMask,
		},
		{
			name: "change-name",
			orig: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					Name: "test-name-repo",
				},
			},
			chgFn: changeName("test-update-name-repo"),
			masks: []string{"Name"},
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					Name: "test-update-name-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-description",
			orig: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					Description: "test-description-repo",
				},
			},
			chgFn: changeDescription("test-update-description-repo"),
			masks: []string{"Description"},
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					Description: "test-update-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-name-and-description",
			orig: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					Name:        "test-name-repo",
					Description: "test-description-repo",
				},
			},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("test-update-name-repo")),
			masks: []string{"Name", "Description"},
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					Name:        "test-update-name-repo",
					Description: "test-update-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "delete-name",
			orig: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					Name:        "test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{"Name"},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("")),
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					Description: "test-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "delete-description",
			orig: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					Name:        "test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{"Description"},
			chgFn: combine(changeDescription(""), changeName("test-update-name-repo")),
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					Name: "test-name-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-name",
			orig: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					Name:        "test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{"Description"},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("")),
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					Name:        "test-name-repo",
					Description: "test-update-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-description",
			orig: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					Name:        "test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{"Name"},
			chgFn: combine(changeDescription(""), changeName("test-update-name-repo")),
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
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
			assert := assert.New(t)
			kms := kms.TestKms(t, conn, wrapper)
			repo, err := NewRepository(rw, rw, kms)
			assert.NoError(err)
			assert.NotNil(repo)
			_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
			tt.orig.ScopeId = prj.GetPublicId()
			orig, err := repo.CreateCatalog(context.Background(), tt.orig)
			require.NoError(t, err)
			require.NotNil(t, orig)

			if tt.chgFn != nil {
				orig = tt.chgFn(orig)
			}
			got, gotCount, err := repo.UpdateCatalog(context.Background(), orig, 1, tt.masks)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Equal(tt.wantCount, gotCount, "row count")
				assert.Nil(got)
				return
			}
			assert.NoError(err)
			assert.Empty(tt.orig.PublicId)
			assert.NotNil(got)
			assertPublicId(t, "hcst", got.PublicId)
			assert.Equal(tt.wantCount, gotCount, "row count")
			assert.NotSame(tt.orig, got)
			assert.Equal(tt.orig.ScopeId, got.ScopeId)
			dbassert := dbassert.New(t, conn.DB())
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
		})
	}

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert := assert.New(t)
		kms := kms.TestKms(t, conn, wrapper)
		repo, err := NewRepository(rw, rw, kms)
		assert.NoError(err)
		assert.NotNil(repo)

		name := "test-dup-name"
		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		cats := TestCatalogs(t, conn, prj.PublicId, 2)
		c1 := cats[0]
		c1.Name = name
		got1, gotCount1, err := repo.UpdateCatalog(context.Background(), c1, 1, []string{"name"})
		assert.NoError(err)
		assert.NotNil(got1)
		assert.Equal(name, got1.Name)
		assert.Equal(1, gotCount1, "row count")

		c2 := cats[1]
		c2.Name = name
		got2, gotCount2, err := repo.UpdateCatalog(context.Background(), c2, 1, []string{"name"})
		assert.Truef(errors.Is(err, errors.ErrNotUnique), "want err: %v got: %v", errors.ErrNotUnique, err)
		assert.Nil(got2)
		assert.Equal(db.NoRowsAffected, gotCount2, "row count")
	})

	t.Run("valid-duplicate-names-diff-scopes", func(t *testing.T) {
		assert := assert.New(t)
		kms := kms.TestKms(t, conn, wrapper)
		repo, err := NewRepository(rw, rw, kms)
		assert.NoError(err)
		assert.NotNil(repo)
		org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		in := &HostCatalog{
			HostCatalog: &store.HostCatalog{
				Name: "test-name-repo",
			},
		}
		in2 := in.clone()

		in.ScopeId = prj.GetPublicId()
		got, err := repo.CreateCatalog(context.Background(), in)
		assert.NoError(err)
		assert.NotNil(got)
		assertPublicId(t, "hcst", got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)

		in2.ScopeId = org.GetPublicId()
		in2.Name = "first-name"
		got2, err := repo.CreateCatalog(context.Background(), in2)
		assert.NoError(err)
		assert.NotNil(got2)
		got2.Name = got.Name
		got3, gotCount3, err := repo.UpdateCatalog(context.Background(), got2, 1, []string{"name"})
		assert.NoError(err)
		assert.NotNil(got3)
		assert.NotSame(got2, got3)
		assert.Equal(got.Name, got3.Name)
		assert.Equal(got2.Description, got3.Description)
		assert.Equal(1, gotCount3, "row count")
	})

	t.Run("change-scope-id", func(t *testing.T) {
		assert := assert.New(t)
		kms := kms.TestKms(t, conn, wrapper)
		repo, err := NewRepository(rw, rw, kms)
		assert.NoError(err)
		assert.NotNil(repo)

		iamRepo := iam.TestRepo(t, conn, wrapper)
		_, prj1 := iam.TestScopes(t, iamRepo)
		_, prj2 := iam.TestScopes(t, iamRepo)
		c1, c2 := testCatalog(t, conn, prj1.PublicId), testCatalog(t, conn, prj2.PublicId)
		assert.NotEqual(c1.ScopeId, c2.ScopeId)
		orig := c1.clone()

		c1.ScopeId = c2.ScopeId
		assert.Equal(c1.ScopeId, c2.ScopeId)

		got1, gotCount1, err := repo.UpdateCatalog(context.Background(), c1, 1, []string{"name"})

		assert.NoError(err)
		assert.NotNil(got1)
		assert.Equal(orig.ScopeId, got1.ScopeId)
		assert.Equal(1, gotCount1, "row count")
	})
}

func TestRepository_LookupCatalog(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cat := testCatalog(t, conn, prj.PublicId)
	badId, err := newHostCatalogId()
	assert.NoError(t, err)
	assert.NotNil(t, badId)

	tests := []struct {
		name    string
		id      string
		want    *HostCatalog
		wantErr errors.Code
	}{
		{
			name: "found",
			id:   cat.GetPublicId(),
			want: cat,
		},
		{
			name: "not-found",
			id:   badId,
			want: nil,
		},
		{
			name:    "bad-public-id",
			id:      "",
			want:    nil,
			wantErr: errors.InvalidParameter,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			kms := kms.TestKms(t, conn, wrapper)
			repo, err := NewRepository(rw, rw, kms)
			assert.NoError(err)
			assert.NotNil(repo)

			got, err := repo.LookupCatalog(context.Background(), tt.id)
			if tt.wantErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				return
			}
			assert.NoError(err)

			switch {
			case tt.want == nil:
				assert.Nil(got)
			case tt.want != nil:
				assert.NotNil(got)
				assert.Equal(got, tt.want)
			}
		})
	}
}

func TestRepository_DeleteCatalog(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cat := testCatalog(t, conn, prj.PublicId)
	badId, err := newHostCatalogId()
	assert.NoError(t, err)
	assert.NotNil(t, badId)

	tests := []struct {
		name    string
		id      string
		want    int
		wantErr errors.Code
	}{
		{
			name: "found",
			id:   cat.GetPublicId(),
			want: 1,
		},
		{
			name: "not-found",
			id:   badId,
			want: 0,
		},
		{
			name:    "bad-public-id",
			id:      "",
			want:    0,
			wantErr: errors.InvalidParameter,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			kms := kms.TestKms(t, conn, wrapper)
			repo, err := NewRepository(rw, rw, kms)
			assert.NoError(err)
			assert.NotNil(repo)

			got, err := repo.DeleteCatalog(context.Background(), tt.id)
			if tt.wantErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				return
			}
			assert.NoError(err)
			assert.Equal(tt.want, got, "row count")
		})
	}
}

func TestRepository_ListCatalogs_Multiple_Scopes(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(rw, rw, kms)
	assert.NoError(t, err)
	assert.NotNil(t, repo)

	const numPerScope = 10
	var projs []string
	var total int
	for i := 0; i < numPerScope; i++ {
		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		projs = append(projs, prj.GetPublicId())
		for j := 0; j < numPerScope; j++ {
			testCatalog(t, conn, prj.PublicId)
			total++
		}
	}

	got, err := repo.ListCatalogs(context.Background(), projs)
	require.NoError(t, err)
	assert.Equal(t, total, len(got))
}
