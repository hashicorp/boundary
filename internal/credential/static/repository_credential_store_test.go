// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package static

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/credential/static/store"
	"github.com/hashicorp/boundary/internal/db"
	dbassert "github.com/hashicorp/boundary/internal/db/assert"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func assertPublicId(t *testing.T, prefix, actual string) {
	t.Helper()
	assert.NotEmpty(t, actual)
	parts := strings.Split(actual, "_")
	assert.Equalf(t, 2, len(parts), "want one '_' in PublicId, got multiple in %q", actual)
	assert.Equalf(t, prefix, parts[0], "PublicId want prefix: %q, got: %q in %q", prefix, parts[0], actual)
}

func TestRepository_CreateCredentialStore(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	tests := []struct {
		name        string
		store       *CredentialStore
		wantErr     bool
		wantErrCode errors.Code
	}{
		{
			name:        "missing-store",
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name:        "missing-embedded-store",
			store:       &CredentialStore{},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "missing-project-id",
			store: &CredentialStore{
				CredentialStore: &store.CredentialStore{},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "public-id-set",
			store: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					ProjectId: prj.PublicId,
					PublicId:  "bad-dont-set-this",
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "valid",
			store: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					ProjectId: prj.PublicId,
				},
			},
		},
		{
			name: "valid-with-name",
			store: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					ProjectId: prj.PublicId,
					Name:      "test-store",
				},
			},
		},
		{
			name: "valid-with-description",
			store: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					ProjectId:   prj.PublicId,
					Description: "test-store-description",
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
			repo, err := NewRepository(ctx, rw, rw, kms)
			require.NoError(err)
			require.NotNil(repo)

			got, err := repo.CreateCredentialStore(ctx, tt.store)
			if tt.wantErr {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			assert.Empty(tt.store.PublicId)
			require.NotNil(got)
			assertPublicId(t, globals.StaticCredentialStorePrefix, got.PublicId)
			assert.NotSame(tt.store, got)
			assert.Equal(got.CreateTime, got.UpdateTime)
			assert.NoError(db.TestVerifyOplog(t, rw, got.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))
		})
	}

	t.Run("duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		repo, err := NewRepository(ctx, rw, rw, kms)
		require.NoError(err)
		require.NotNil(repo)
		org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		prj2 := iam.TestProject(t, iam.TestRepo(t, conn, wrapper), org.GetPublicId())
		require.NoError(err)

		in, err := NewCredentialStore(prj.GetPublicId(), WithName("my-name"), WithDescription("desc"))
		assert.NoError(err)

		got, err := repo.CreateCredentialStore(ctx, in)
		require.NoError(err)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)

		in2, err := NewCredentialStore(prj.GetPublicId(), WithName("my-name"), WithDescription("desc"))
		require.NoError(err)
		got2, err := repo.CreateCredentialStore(ctx, in2)
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "want err code: %v got err: %v", errors.NotUnique, err)
		assert.Nil(got2)

		// Creating credential in different project should not conflict
		in3, err := NewCredentialStore(prj2.GetPublicId(), WithName("my-name"), WithDescription("desc"))
		require.NoError(err)
		got3, err := repo.CreateCredentialStore(ctx, in3)
		require.NoError(err)
		assert.Equal(in.Name, got3.Name)
		assert.Equal(in3.Name, got3.Name)
		assert.Equal(in3.Description, got3.Description)

		assert.NotEqual(got.PublicId, got3.PublicId)
	})
}

func TestRepository_LookupCredentialStore(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	store := TestCredentialStore(t, conn, wrapper, prj.PublicId)

	tests := []struct {
		name    string
		id      string
		want    *CredentialStore
		wantErr errors.Code
	}{
		{
			name: "valid-with-client-cert",
			id:   store.GetPublicId(),
			want: store,
		},
		{
			name:    "empty-public-id",
			id:      "",
			wantErr: errors.InvalidParameter,
		},
		{
			name: "not-found",
			id:   "cs_fake",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			kms := kms.TestKms(t, conn, wrapper)
			repo, err := NewRepository(ctx, rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)

			got, err := repo.LookupCredentialStore(ctx, tt.id)
			if tt.wantErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)

			if tt.want == nil {
				assert.Nil(got)
				return
			}
			assert.NotNil(got)
			assert.Equal(got, tt.want)
		})
	}
}

func TestRepository_UpdateCredentialStore(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	changeName := func(n string) func(*CredentialStore) *CredentialStore {
		return func(cs *CredentialStore) *CredentialStore {
			cs.Name = n
			return cs
		}
	}

	changeDescription := func(d string) func(*CredentialStore) *CredentialStore {
		return func(cs *CredentialStore) *CredentialStore {
			cs.Description = d
			return cs
		}
	}

	makeNil := func() func(*CredentialStore) *CredentialStore {
		return func(cs *CredentialStore) *CredentialStore {
			return nil
		}
	}

	makeEmbeddedNil := func() func(*CredentialStore) *CredentialStore {
		return func(cs *CredentialStore) *CredentialStore {
			return &CredentialStore{}
		}
	}

	deletePublicId := func() func(*CredentialStore) *CredentialStore {
		return func(cs *CredentialStore) *CredentialStore {
			cs.PublicId = ""
			return cs
		}
	}

	nonExistentPublicId := func() func(*CredentialStore) *CredentialStore {
		return func(cs *CredentialStore) *CredentialStore {
			cs.PublicId = "abcd_OOOOOOOOOO"
			return cs
		}
	}

	combine := func(fns ...func(cs *CredentialStore) *CredentialStore) func(*CredentialStore) *CredentialStore {
		return func(cs *CredentialStore) *CredentialStore {
			for _, fn := range fns {
				cs = fn(cs)
			}
			return cs
		}
	}

	tests := []struct {
		name      string
		orig      *CredentialStore
		chgFn     func(*CredentialStore) *CredentialStore
		masks     []string
		want      *CredentialStore
		wantCount int
		wantErr   errors.Code
	}{
		{
			name: "nil-credential-store",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{},
			},
			chgFn:   makeNil(),
			masks:   []string{"Name", "Description"},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "nil-embedded-credential-store",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{},
			},
			chgFn:   makeEmbeddedNil(),
			masks:   []string{"Name", "Description"},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "no-public-id",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{},
			},
			chgFn:   deletePublicId(),
			masks:   []string{"Name", "Description"},
			wantErr: errors.InvalidPublicId,
		},
		{
			name: "updating-non-existent-credential-store",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Name: "test-name-repo",
				},
			},
			chgFn:   combine(nonExistentPublicId(), changeName("test-update-name-repo")),
			masks:   []string{"Name"},
			wantErr: errors.RecordNotFound,
		},
		{
			name: "empty-field-mask",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Name: "test-name-repo",
				},
			},
			chgFn:   changeName("test-update-name-repo"),
			wantErr: errors.EmptyFieldMask,
		},
		{
			name: "read-only-fields-in-field-mask",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Name: "test-name-repo",
				},
			},
			chgFn:   changeName("test-update-name-repo"),
			masks:   []string{"PublicId", "CreateTime", "UpdateTime", "ProjectId"},
			wantErr: errors.InvalidFieldMask,
		},
		{
			name: "unknown-field-in-field-mask",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Name: "test-name-repo",
				},
			},
			chgFn:   changeName("test-update-name-repo"),
			masks:   []string{"Bilbo"},
			wantErr: errors.InvalidFieldMask,
		},
		{
			name: "change-name",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Name: "test-name-repo",
				},
			},
			chgFn: changeName("test-update-name-repo"),
			masks: []string{"Name"},
			want: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Name: "test-update-name-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-description",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Description: "test-description-repo",
				},
			},
			chgFn: changeDescription("test-update-description-repo"),
			masks: []string{"Description"},
			want: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Description: "test-update-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-name-and-description",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Name:        "test-name-repo",
					Description: "test-description-repo",
				},
			},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("test-update-name-repo")),
			masks: []string{"Name", "Description"},
			want: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Name:        "test-update-name-repo",
					Description: "test-update-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "delete-name",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Name:        "test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{"Name"},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("")),
			want: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Description: "test-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "delete-description",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Name:        "test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{"Description"},
			chgFn: combine(changeDescription(""), changeName("test-update-name-repo")),
			want: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Name: "test-name-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-name",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Name:        "test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{"Description"},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("")),
			want: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Name:        "test-name-repo",
					Description: "test-update-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-description",
			orig: &CredentialStore{
				CredentialStore: &store.CredentialStore{
					Name:        "test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{"Name"},
			chgFn: combine(changeDescription(""), changeName("test-update-name-repo")),
			want: &CredentialStore{
				CredentialStore: &store.CredentialStore{
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
			ctx := context.Background()
			kms := kms.TestKms(t, conn, wrapper)
			repo, err := NewRepository(ctx, rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)

			_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
			tt.orig.ProjectId = prj.GetPublicId()

			orig, err := repo.CreateCredentialStore(ctx, tt.orig)
			assert.NoError(err)
			require.NotNil(orig)

			if tt.chgFn != nil {
				orig = tt.chgFn(orig)
			}
			got, gotCount, err := repo.UpdateCredentialStore(ctx, orig, 1, tt.masks)
			if tt.wantErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				assert.Equal(tt.wantCount, gotCount, "row count")
				assert.Nil(got)
				return
			}
			assert.NoError(err)
			assert.Empty(tt.orig.PublicId)
			require.NotNil(got)
			assertPublicId(t, globals.StaticCredentialStorePrefix, got.PublicId)
			assert.Equal(tt.wantCount, gotCount, "row count")
			assert.NotSame(tt.orig, got)
			assert.Equal(tt.orig.ProjectId, got.ProjectId)
			underlyingDB, err := conn.SqlDB(ctx)
			require.NoError(err)
			dbassert := dbassert.New(t, underlyingDB)
			if tt.want.Name == "" {
				dbassert.IsNull(got, "name")
			} else {
				assert.Equal(tt.want.Name, got.Name)
			}

			if tt.want.Description == "" {
				dbassert.IsNull(got, "description")
			} else {
				assert.Equal(tt.want.Description, got.Description)
			}

			if tt.wantCount > 0 {
				assert.NoError(db.TestVerifyOplog(t, rw, got.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
			}
		})
	}

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		repo, err := NewRepository(ctx, rw, rw, kms)
		assert.NoError(err)
		require.NotNil(repo)
		require.NoError(err)

		name := "test-dup-name"
		_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		css := TestCredentialStores(t, conn, wrapper, prj.PublicId, 2)

		csA, csB := css[0], css[1]

		csA.Name = name
		got1, gotCount1, err := repo.UpdateCredentialStore(ctx, csA, 1, []string{"Name"})
		assert.NoError(err)
		require.NotNil(got1)
		assert.Equal(name, got1.Name)
		assert.Equal(1, gotCount1, "row count")
		assert.NoError(db.TestVerifyOplog(t, rw, csA.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))

		csB.Name = name
		got2, gotCount2, err := repo.UpdateCredentialStore(ctx, csB, 1, []string{"Name"})
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "want err code: %v got err: %v", errors.NotUnique, err)
		assert.Nil(got2)
		assert.Equal(db.NoRowsAffected, gotCount2, "row count")
	})

	t.Run("valid-duplicate-names-diff-projects", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		repo, err := NewRepository(ctx, rw, rw, kms)
		assert.NoError(err)
		require.NotNil(repo)

		org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		prj2 := iam.TestProject(t, iam.TestRepo(t, conn, wrapper), org.GetPublicId())
		in := &CredentialStore{
			CredentialStore: &store.CredentialStore{
				Name: "test-name-repo",
			},
		}
		in2 := in.clone()

		in.ProjectId = prj.GetPublicId()
		got, err := repo.CreateCredentialStore(ctx, in)
		assert.NoError(err)
		require.NotNil(got)
		assertPublicId(t, globals.StaticCredentialStorePrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)

		in2.ProjectId = prj2.GetPublicId()
		in2.Name = "first-name"
		got2, err := repo.CreateCredentialStore(ctx, in2)
		assert.NoError(err)
		require.NotNil(got2)
		got2.Name = got.Name
		got3, gotCount3, err := repo.UpdateCredentialStore(ctx, got2, 1, []string{"Name"})
		assert.NoError(err)
		require.NotNil(got3)
		assert.NotSame(got2, got3)
		assert.Equal(got.Name, got3.Name)
		assert.Equal(got2.Description, got3.Description)
		assert.Equal(1, gotCount3, "row count")
	})

	t.Run("change-project-id", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		repo, err := NewRepository(ctx, rw, rw, kms)
		assert.NoError(err)
		require.NotNil(repo)

		iamRepo := iam.TestRepo(t, conn, wrapper)
		_, prj1 := iam.TestScopes(t, iamRepo)
		_, prj2 := iam.TestScopes(t, iamRepo)
		csA, csB := TestCredentialStores(t, conn, wrapper, prj1.PublicId, 1)[0], TestCredentialStores(t, conn, wrapper, prj2.PublicId, 1)[0]
		assert.NotEqual(csA.ProjectId, csB.ProjectId)
		orig := csA.clone()

		csA.ProjectId = csB.ProjectId
		assert.Equal(csA.ProjectId, csB.ProjectId)

		got1, gotCount1, err := repo.UpdateCredentialStore(ctx, csA, 1, []string{"Name"})

		assert.NoError(err)
		require.NotNil(got1)
		assert.Equal(orig.ProjectId, got1.ProjectId)
		assert.Equal(1, gotCount1, "row count")
	})
}

func TestRepository_DeleteCredentialStore(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	kms := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	store := TestCredentialStore(t, conn, wrapper, prj.PublicId)

	tests := []struct {
		name        string
		in          string
		want        int
		wantErr     bool
		wantErrCode errors.Code
	}{
		{
			name:        "With no public id",
			wantErr:     true,
			wantErrCode: errors.InvalidPublicId,
		},
		{
			name: "With non existing account id",
			in:   "cs_fakeid",
			want: 0,
		},
		{
			name: "With existing account id",
			in:   store.GetPublicId(),
			want: 1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(context.Background(), rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.DeleteCredentialStore(context.Background(), tt.in)
			if tt.wantErr {
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "Unexpected error %s", err)
				return
			}
			require.NoError(err)
			assert.EqualValues(tt.want, got)
		})
	}
}
