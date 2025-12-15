// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package target_test

import (
	"context"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/alias/target"
	"github.com/hashicorp/boundary/internal/alias/target/store"
	"github.com/hashicorp/boundary/internal/db"
	dbassert "github.com/hashicorp/boundary/internal/db/assert"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/target/tcp"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_CreateAlias(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	require.NoError(t, kmsCache.CreateKeys(context.Background(), scope.Global.String(), kms.WithRandomReader(rand.Reader)))

	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	tar := tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "test-target-1")

	tests := []struct {
		name        string
		in          *target.Alias
		opts        []target.Option
		want        *target.Alias
		errContains string
	}{
		{
			name:        "nil-alias",
			errContains: "nil Alias",
		},
		{
			name:        "nil-embedded-alias",
			in:          &target.Alias{},
			errContains: "nil embedded Alias",
		},
		{
			name: "no-value",
			in: &target.Alias{Alias: &store.Alias{
				ScopeId: "global",
			}},
			errContains: "no value",
		},
		{
			name: "no-scope",
			in: &target.Alias{Alias: &store.Alias{
				Value: "global",
			}},
			errContains: "no scope",
		},
		{
			name: "specified-public-id",
			in: &target.Alias{
				Alias: &store.Alias{
					PublicId: "alt_1234567890",
					ScopeId:  "global",
					Value:    "specified-public-id",
				},
			},
			errContains: "public id not empty",
		},
		{
			name: "invalid-alias-value",
			in: &target.Alias{
				Alias: &store.Alias{
					ScopeId: "global",
					Value:   "invalid_alias",
				},
			},
			errContains: "contains invalid characters",
		},
		{
			name: "valid-with-value",
			in: &target.Alias{
				Alias: &store.Alias{
					ScopeId: "global",
					Value:   "valid-with-value",
				},
			},
			want: &target.Alias{
				Alias: &store.Alias{
					ScopeId: "global",
					Value:   "valid-with-value",
				},
			},
		},
		{
			name: "valid-with-name",
			in: &target.Alias{
				Alias: &store.Alias{
					ScopeId: "global",
					Value:   "valid-with-name",
					Name:    "test-name-repo",
				},
			},
			want: &target.Alias{
				Alias: &store.Alias{
					ScopeId: "global",
					Value:   "valid-with-name",
					Name:    "test-name-repo",
				},
			},
		},
		{
			name: "valid-with-description",
			in: &target.Alias{
				Alias: &store.Alias{
					ScopeId:     "global",
					Value:       "valid-with-description",
					Description: ("test-description-repo"),
				},
			},
			want: &target.Alias{
				Alias: &store.Alias{
					ScopeId:     "global",
					Value:       "valid-with-description",
					Description: ("test-description-repo"),
				},
			},
		},
		{
			name: "valid-with-destination-id",
			in: &target.Alias{
				Alias: &store.Alias{
					ScopeId:       "global",
					Value:         "valid.with.destination.id",
					DestinationId: tar.GetPublicId(),
				},
			},
			want: &target.Alias{
				Alias: &store.Alias{
					ScopeId:       "global",
					Value:         "valid.with.destination.id",
					DestinationId: tar.GetPublicId(),
				},
			},
		},
		{
			name: "unknown-destination-id",
			in: &target.Alias{
				Alias: &store.Alias{
					ScopeId:       "global",
					Value:         "unknown.destination.id",
					DestinationId: "ttcp_unknownid",
				},
			},
			errContains: `target with specified destination id "ttcp_unknownid" was not found`,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			repo, err := target.NewRepository(ctx, rw, rw, kmsCache)
			assert.NoError(err)
			assert.NotNil(repo)
			got, err := repo.CreateAlias(ctx, tt.in, tt.opts...)
			if tt.errContains != "" {
				assert.ErrorContains(err, tt.errContains)
				assert.Nil(got)
				return
			}
			require.NoError(t, err)
			assert.Empty(tt.in.PublicId)
			assert.NotNil(t, got)
			assertPublicId(t, "alt", got.PublicId)
			assert.NotSame(tt.in, got)
			assert.Equal(tt.want.Value, got.Value)
			assert.Equal(tt.want.Description, got.Description)
			assert.Equal(got.CreateTime, got.UpdateTime)
		})
	}

	t.Run("invalid-duplicate-aliases-case-insensitive", func(t *testing.T) {
		assert := assert.New(t)
		kms := kms.TestKms(t, conn, wrapper)
		repo, err := target.NewRepository(ctx, rw, rw, kms)
		assert.NoError(err)
		assert.NotNil(repo)
		in := &target.Alias{
			Alias: &store.Alias{
				ScopeId: "global",
				Value:   "test-value-repo",
			},
		}

		got, err := repo.CreateAlias(ctx, in)
		assert.NoError(err)
		require.NotNil(t, got)
		assertPublicId(t, "alt", got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Value, got.Value)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		in.Value = "TEST-VALUE-REPO"
		got2, err := repo.CreateAlias(ctx, in)
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "want err code: %v got err: %v", errors.NotUnique, err)
		assert.Nil(got2)
	})

	t.Run("invalid-duplicate-name", func(t *testing.T) {
		assert := assert.New(t)
		kms := kms.TestKms(t, conn, wrapper)
		repo, err := target.NewRepository(ctx, rw, rw, kms)
		assert.NoError(err)
		assert.NotNil(repo)
		in := &target.Alias{
			Alias: &store.Alias{
				ScopeId: "global",
				Value:   "test-value-name-1",
			},
		}

		got, err := repo.CreateAlias(ctx, in)
		assert.NoError(err)
		require.NotNil(t, got)
		assertPublicId(t, "alt", got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Value, got.Value)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		got2, err := repo.CreateAlias(ctx, in)
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "want err code: %v got err: %v", errors.NotUnique, err)
		assert.Nil(got2)
	})
}

func assertPublicId(t *testing.T, prefix, actual string) {
	t.Helper()
	assert.NotEmpty(t, actual)
	parts := strings.Split(actual, "_")
	assert.Equalf(t, 2, len(parts), "want one '_' in PublicId, got multiple in %q", actual)
	assert.Equalf(t, prefix, parts[0], "PublicId want prefix: %q, got: %q in %q", prefix, parts[0], actual)
}

func TestRepository_UpdateAlias(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	ctx := context.Background()
	kmsCache := kms.TestKms(t, conn, wrapper)
	require.NoError(t, kmsCache.CreateKeys(context.Background(), scope.Global.String(), kms.WithRandomReader(rand.Reader)))

	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	tar1 := tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "test-target-1")
	tar2 := tcp.TestTarget(ctx, t, conn, proj.GetPublicId(), "test-target-2")

	_, _ = tar1, tar2

	repo, err := target.NewRepository(ctx, rw, rw, kmsCache)
	assert.NoError(t, err)
	assert.NotNil(t, repo)

	changeValue := func(s string) func(*target.Alias) *target.Alias {
		return func(c *target.Alias) *target.Alias {
			c.Value = s
			return c
		}
	}

	changeName := func(s string) func(*target.Alias) *target.Alias {
		return func(c *target.Alias) *target.Alias {
			c.Name = s
			return c
		}
	}

	changeDestinationId := func(s string) func(*target.Alias) *target.Alias {
		return func(c *target.Alias) *target.Alias {
			c.DestinationId = s
			return c
		}
	}

	changeHostId := func(s string) func(*target.Alias) *target.Alias {
		return func(c *target.Alias) *target.Alias {
			c.HostId = s
			return c
		}
	}

	changeDescription := func(s string) func(*target.Alias) *target.Alias {
		return func(c *target.Alias) *target.Alias {
			c.Description = s
			return c
		}
	}

	makeNil := func() func(*target.Alias) *target.Alias {
		return func(c *target.Alias) *target.Alias {
			return nil
		}
	}

	makeEmbeddedNil := func() func(*target.Alias) *target.Alias {
		return func(c *target.Alias) *target.Alias {
			return &target.Alias{}
		}
	}

	deletePublicId := func() func(*target.Alias) *target.Alias {
		return func(c *target.Alias) *target.Alias {
			c.PublicId = ""
			return c
		}
	}

	nonExistentPublicId := func() func(*target.Alias) *target.Alias {
		return func(c *target.Alias) *target.Alias {
			c.PublicId = "alt_OOOOOOOOOO"
			return c
		}
	}

	combine := func(fns ...func(c *target.Alias) *target.Alias) func(*target.Alias) *target.Alias {
		return func(c *target.Alias) *target.Alias {
			for _, fn := range fns {
				c = fn(c)
			}
			return c
		}
	}

	tests := []struct {
		name      string
		orig      *target.Alias
		chgFn     func(*target.Alias) *target.Alias
		masks     []string
		want      *target.Alias
		wantCount int
		wantIsErr errors.Code
	}{
		{
			name: "nil-alias",
			orig: &target.Alias{
				Alias: &store.Alias{
					Value: "nil-alias",
				},
			},
			chgFn:     makeNil(),
			masks:     []string{"Value", "Description"},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "nil-embedded-alias",
			orig: &target.Alias{
				Alias: &store.Alias{
					Value: "nil-embedded-alias",
				},
			},
			chgFn:     makeEmbeddedNil(),
			masks:     []string{"Value", "Description"},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "no-public-id",
			orig: &target.Alias{
				Alias: &store.Alias{
					Value: "no-public-id",
				},
			},
			chgFn:     deletePublicId(),
			masks:     []string{"Value", "Description"},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "updating-non-existent-alias",
			orig: &target.Alias{
				Alias: &store.Alias{
					Value: "updating-non-existent-alias",
				},
			},
			chgFn:     combine(nonExistentPublicId(), changeValue("test-update-name-repo")),
			masks:     []string{"Value"},
			wantIsErr: errors.RecordNotFound,
		},
		{
			name: "empty-field-mask",
			orig: &target.Alias{
				Alias: &store.Alias{
					Value: "empty-field-mask",
				},
			},
			chgFn:     changeValue("test-update-name-repo"),
			wantIsErr: errors.EmptyFieldMask,
		},
		{
			name: "read-only-fields-in-field-mask",
			orig: &target.Alias{
				Alias: &store.Alias{
					Value: "read-only-fields-in-field-mask",
				},
			},
			chgFn:     changeValue("test-update-name-repo"),
			masks:     []string{"PublicId", "CreateTime", "UpdateTime", "ScopeId"},
			wantIsErr: errors.InvalidFieldMask,
		},
		{
			name: "unknown-field-in-field-mask",
			orig: &target.Alias{
				Alias: &store.Alias{
					Value: "unknown-field-in-field-mask",
				},
			},
			chgFn:     changeValue("test-update-name-repo"),
			masks:     []string{"Bilbo"},
			wantIsErr: errors.InvalidFieldMask,
		},
		{
			name: "change-value",
			orig: &target.Alias{
				Alias: &store.Alias{
					Value: "change-value",
				},
			},
			chgFn: changeValue("change-value-updated"),
			masks: []string{"Value"},
			want: &target.Alias{
				Alias: &store.Alias{
					Value: "change-value-updated",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-name",
			orig: &target.Alias{
				Alias: &store.Alias{
					Value: "change-name",
					Name:  "change-name",
				},
			},
			chgFn: changeName("change-name-updated"),
			masks: []string{"Name"},
			want: &target.Alias{
				Alias: &store.Alias{
					Value: "change-name",
					Name:  "change-name-updated",
				},
			},
			wantCount: 1,
		},
		{
			name: "clear-name",
			orig: &target.Alias{
				Alias: &store.Alias{
					Value: "clear-name",
					Name:  "clear-name",
				},
			},
			chgFn: changeName(""),
			masks: []string{"Name"},
			want: &target.Alias{
				Alias: &store.Alias{
					Value: "clear-name",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-destination-id",
			orig: &target.Alias{
				Alias: &store.Alias{
					Value:         "change-destination-id",
					DestinationId: tar1.GetPublicId(),
				},
			},
			chgFn: changeDestinationId(tar2.GetPublicId()),
			masks: []string{"DestinationId"},
			want: &target.Alias{
				Alias: &store.Alias{
					Value:         "change-destination-id",
					DestinationId: tar2.GetPublicId(),
				},
			},
			wantCount: 1,
		},
		{
			name: "change-destination-id-to-unknown",
			orig: &target.Alias{
				Alias: &store.Alias{
					Value:         "change-destination-id-to-unknown",
					DestinationId: tar1.GetPublicId(),
				},
			},
			chgFn:     changeDestinationId("ttcp_unknownid"),
			masks:     []string{"DestinationId"},
			wantIsErr: errors.NotFound,
		},
		{
			name: "delete-destination-id",
			orig: &target.Alias{
				Alias: &store.Alias{
					Value:         "delete-destination-id",
					DestinationId: tar1.GetPublicId(),
				},
			},
			chgFn: changeDestinationId(tar2.GetPublicId()),
			masks: []string{"DestinationId"},
			want: &target.Alias{
				Alias: &store.Alias{
					Value: "delete-destination-id",
				},
			},
			wantCount: 1,
		},
		{
			name: "delete-destination-also-deletes-host-id",
			orig: &target.Alias{
				Alias: &store.Alias{
					Value:         "delete-destination-also-deletes-host-id",
					DestinationId: tar1.GetPublicId(),
					HostId:        "hst_1234567890",
				},
			},
			chgFn: changeDestinationId(""),
			masks: []string{"DestinationId"},
			want: &target.Alias{
				Alias: &store.Alias{
					Value: "delete-destination-also-deletes-host-id",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-host-id",
			orig: &target.Alias{
				Alias: &store.Alias{
					Value:         "change-host-id",
					DestinationId: tar1.GetPublicId(),
					HostId:        "hst_1234567890",
				},
			},
			chgFn: changeHostId("hst_0987654321"),
			masks: []string{"HostId"},
			want: &target.Alias{
				Alias: &store.Alias{
					Value:         "change-host-id",
					DestinationId: tar1.GetPublicId(),
					HostId:        "hst_0987654321",
				},
			},
			wantCount: 1,
		},
		{
			name: "delete-host-id",
			orig: &target.Alias{
				Alias: &store.Alias{
					Value:         "delete-host-id",
					DestinationId: tar1.GetPublicId(),
					HostId:        "hst_1234567890",
				},
			},
			chgFn: changeHostId(""),
			masks: []string{"HostId"},
			want: &target.Alias{
				Alias: &store.Alias{
					Value:         "delete-host-id",
					DestinationId: tar1.GetPublicId(),
				},
			},
			wantCount: 1,
		},
		{
			name: "change-description",
			orig: &target.Alias{
				Alias: &store.Alias{
					Value:       "change-description",
					Description: "test-description-repo",
				},
			},
			chgFn: changeDescription("test-update-description-repo"),
			masks: []string{"Description"},
			want: &target.Alias{
				Alias: &store.Alias{
					Value:       "change-description",
					Description: "test-update-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-value-and-description",
			orig: &target.Alias{
				Alias: &store.Alias{
					Value:       "change-value-and-description",
					Description: "test-description-repo",
				},
			},
			chgFn: combine(changeDescription("test-update-description-repo"), changeValue("change-value-and-description-updated")),
			masks: []string{"Value", "Description"},
			want: &target.Alias{
				Alias: &store.Alias{
					Value:       "change-value-and-description-updated",
					Description: "test-update-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "delete-value",
			orig: &target.Alias{
				Alias: &store.Alias{
					Value: "delete-value",
				},
			},
			masks:     []string{"Value"},
			chgFn:     combine(changeDescription("test-update-description-repo"), changeValue("")),
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "delete-description",
			orig: &target.Alias{
				Alias: &store.Alias{
					Value:       "delete-description",
					Description: "test-description-repo",
				},
			},
			masks: []string{"Description"},
			chgFn: combine(changeDescription(""), changeValue("delete-description-updated")),
			want: &target.Alias{
				Alias: &store.Alias{
					Value: "delete-description",
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-value",
			orig: &target.Alias{
				Alias: &store.Alias{
					Value:       "do-not-delete-value",
					Description: "test-description-repo",
				},
			},
			masks: []string{"Description"},
			chgFn: combine(changeDescription("test-update-description-repo"), changeValue("")),
			want: &target.Alias{
				Alias: &store.Alias{
					Value:       "do-not-delete-value",
					Description: "test-update-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-description",
			orig: &target.Alias{
				Alias: &store.Alias{
					Value:       "do-not-delete-description",
					Description: "test-description-repo",
				},
			},
			masks: []string{"Value"},
			chgFn: combine(changeDescription(""), changeValue("do-not-delete-description-updated")),
			want: &target.Alias{
				Alias: &store.Alias{
					Value:       "do-not-delete-description-updated",
					Description: "test-description-repo",
				},
			},
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			tt.orig.ScopeId = "global"
			orig, err := repo.CreateAlias(ctx, tt.orig)
			require.NoError(t, err)
			require.NotNil(t, orig)

			if tt.chgFn != nil {
				orig = tt.chgFn(orig)
			}
			got, gotCount, err := repo.UpdateAlias(ctx, orig, 1, tt.masks)
			if tt.wantIsErr != 0 {
				assert.Truef(t, errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Equal(t, tt.wantCount, gotCount, "row count")
				assert.Nil(t, got)
				return
			}
			assert.NoError(t, err)
			assert.Empty(t, tt.orig.PublicId)
			assert.NotNil(t, got)
			assertPublicId(t, "alt", got.PublicId)
			assert.Equal(t, tt.wantCount, gotCount, "row count")
			assert.NotSame(t, tt.orig, got)
			assert.Equal(t, tt.orig.ScopeId, got.ScopeId)
			underlyingDB, err := conn.SqlDB(ctx)
			require.NoError(t, err)
			dbassert := dbassert.New(t, underlyingDB)
			if tt.want.Value == "" {
				dbassert.IsNull(got, "value")
				return
			}
			assert.Equal(t, tt.want.Value, got.Value)
			if tt.want.Description == "" {
				dbassert.IsNull(got, "description")
				return
			}
			assert.Equal(t, tt.want.Description, got.Description)
		})
	}

	t.Run("invalid-duplicate-values", func(t *testing.T) {
		value := "test-dup-value"
		c1 := target.TestAlias(t, db.New(conn), "test")
		c1.Value = value
		got1, gotCount1, err := repo.UpdateAlias(context.Background(), c1, 1, []string{"value"})
		assert.NoError(t, err)
		assert.NotNil(t, got1)
		assert.Equal(t, value, got1.Value)
		assert.Equal(t, 1, gotCount1, "row count")

		c2 := target.TestAlias(t, db.New(conn), "test2")
		c2.Value = value
		got2, gotCount2, err := repo.UpdateAlias(context.Background(), c2, 1, []string{"value"})
		assert.Truef(t, errors.Match(errors.T(errors.NotUnique), err), "want err code: %v got err: %v", errors.NotUnique, err)
		assert.Nil(t, got2)
		assert.Equal(t, db.NoRowsAffected, gotCount2, "row count")
	})

	t.Run("invalid-duplicate-name", func(t *testing.T) {
		name := "test-dup-name"
		c1 := target.TestAlias(t, db.New(conn), "duplicate.name.test")
		c1.Name = name
		got1, gotCount1, err := repo.UpdateAlias(context.Background(), c1, 1, []string{"name"})
		assert.NoError(t, err)
		assert.NotNil(t, got1)
		assert.Equal(t, name, got1.Name)
		assert.Equal(t, 1, gotCount1, "row count")

		c2 := target.TestAlias(t, db.New(conn), "duplicate.name.test2")
		c2.Name = name
		got2, gotCount2, err := repo.UpdateAlias(context.Background(), c2, 1, []string{"name"})
		assert.Truef(t, errors.Match(errors.T(errors.NotUnique), err), "want err code: %v got err: %v", errors.NotUnique, err)
		assert.Nil(t, got2)
		assert.Equal(t, db.NoRowsAffected, gotCount2, "row count")
	})

	t.Run("invalid-alias", func(t *testing.T) {
		value := "invalid_alais"
		c1 := target.TestAlias(t, db.New(conn), "test")
		c1.Value = value
		got1, gotCount1, err := repo.UpdateAlias(context.Background(), c1, 1, []string{"value"})
		assert.Error(t, err)
		assert.ErrorContains(t, err, "contains invalid characters")
		assert.Nil(t, got1)
		assert.Equal(t, db.NoRowsAffected, gotCount1, "row count")
	})
}

func TestRepository_LookupAlias(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	al := target.TestAlias(t, rw, "one")
	badId, err := db.NewPublicId(ctx, globals.TargetAliasPrefix)
	assert.NoError(t, err)
	assert.NotNil(t, badId)

	tests := []struct {
		name    string
		id      string
		want    *target.Alias
		wantErr errors.Code
	}{
		{
			name: "found",
			id:   al.GetPublicId(),
			want: al,
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
			repo, err := target.NewRepository(ctx, rw, rw, kms)
			assert.NoError(err)
			assert.NotNil(repo)

			got, err := repo.LookupAlias(ctx, tt.id)
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

func TestRepository_DeleteAlias(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	kmsCache := kms.TestKms(t, conn, wrapper)
	require.NoError(t, kmsCache.CreateKeys(context.Background(), scope.Global.String(), kms.WithRandomReader(rand.Reader)))

	repo, err := target.NewRepository(ctx, rw, rw, kmsCache)
	assert.NoError(t, err)
	require.NotNil(t, repo)

	al := target.TestAlias(t, rw, "deleted.alias")
	badId, err := db.NewPublicId(ctx, globals.TargetAliasPrefix)
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
			id:   al.GetPublicId(),
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
			got, err := repo.DeleteAlias(ctx, tt.id)
			if tt.wantErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(tt.want, got, "row count")
		})
	}
}
