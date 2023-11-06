// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package password

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/password/store"
	"github.com/hashicorp/boundary/internal/db"
	dbassert "github.com/hashicorp/boundary/internal/db/assert"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestRepository_CreateAuthMethod(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	tests := []struct {
		name       string
		in         *AuthMethod
		opts       []Option
		want       *AuthMethod
		wantIsErr  errors.Code
		wantErrMsg string
	}{
		{
			name:       "nil-AuthMethod",
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "password.(Repository).CreateAuthMethod: missing AuthMethod: parameter violation: error #100",
		},
		{
			name:       "nil-embedded-AuthMethod",
			in:         &AuthMethod{},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "password.(Repository).CreateAuthMethod: missing embedded AuthMethod: parameter violation: error #100",
		},
		{
			name: "invalid-no-scope-id",
			in: &AuthMethod{
				AuthMethod: &store.AuthMethod{},
			},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "password.(Repository).CreateAuthMethod: missing scope id: parameter violation: error #100",
		},
		{
			name: "invalid-public-id-set",
			in: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					ScopeId:  org.PublicId,
					PublicId: "hcst_OOOOOOOOOO",
				},
			},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "password.(Repository).CreateAuthMethod: public id not empty: parameter violation: error #100",
		},
		{
			name: "valid-no-options",
			in: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					ScopeId: org.PublicId,
				},
			},
			want: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					ScopeId: org.PublicId,
				},
			},
		},
		{
			name: "valid-with-name",
			in: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					ScopeId: org.PublicId,
					Name:    "test-name-repo",
				},
			},
			want: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					ScopeId: org.PublicId,
					Name:    "test-name-repo",
				},
			},
		},
		{
			name: "valid-with-description",
			in: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					ScopeId:     org.PublicId,
					Description: ("test-description-repo"),
				},
			},
			want: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					ScopeId:     org.PublicId,
					Description: ("test-description-repo"),
				},
			},
		},
		{
			name: "invalid-with-config-nil-embedded-config",
			in: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					ScopeId: org.PublicId,
				},
			},
			opts: []Option{
				WithConfiguration(&Argon2Configuration{}),
			},
			wantIsErr:  errors.PasswordInvalidConfiguration,
			wantErrMsg: "password.(Repository).CreateAuthMethod: password.(Argon2Configuration).validate: missing embedded config: password violation: error #202",
		},
		{
			name: "invalid-with-config-unknown-config-type",
			in: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					ScopeId: org.PublicId,
				},
			},
			opts: []Option{
				WithConfiguration(tconf(0)),
			},
			wantIsErr:  errors.PasswordUnsupportedConfiguration,
			wantErrMsg: "password.(Repository).CreateAuthMethod: unknown configuration: password violation: error #201",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kms)
			require.NoError(err)
			require.NotNil(repo)
			got, err := repo.CreateAuthMethod(ctx, tt.in, tt.opts...)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			require.NoError(err)
			assert.Empty(tt.in.PublicId)
			require.NotNil(got)
			assertPublicId(t, globals.PasswordAuthMethodPrefix, got.PublicId)
			assert.NotSame(tt.in, got)
			assert.Equal(tt.want.Name, got.Name)
			assert.Equal(tt.want.Description, got.Description)
			assert.Equal(got.CreateTime, got.UpdateTime)
		})
	}
}

func TestRepository_CreateAuthMethod_DupeNames(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(ctx, rw, rw, kms)
		require.NoError(err)
		require.NotNil(repo)

		org, _ := iam.TestScopes(t, iamRepo)
		in := &AuthMethod{
			AuthMethod: &store.AuthMethod{
				ScopeId: org.GetPublicId(),
				Name:    "test-name-repo",
			},
		}

		got, err := repo.CreateAuthMethod(ctx, in)
		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, globals.PasswordAuthMethodPrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		got2, err := repo.CreateAuthMethod(ctx, in)
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "Unexpected error %s", err)
		assert.Nil(got2)
	})

	t.Run("valid-duplicate-names-diff-scopes", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(ctx, rw, rw, kms)
		require.NoError(err)
		require.NotNil(repo)

		org1, _ := iam.TestScopes(t, iamRepo)
		in := &AuthMethod{
			AuthMethod: &store.AuthMethod{
				Name: "test-name-repo",
			},
		}
		in2 := in.Clone()

		in.ScopeId = org1.GetPublicId()
		got, err := repo.CreateAuthMethod(ctx, in)
		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, globals.PasswordAuthMethodPrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		org2, _ := iam.TestScopes(t, iamRepo)
		in2.ScopeId = org2.GetPublicId()
		got2, err := repo.CreateAuthMethod(ctx, in2)
		require.NoError(err)
		require.NotNil(got2)
		assertPublicId(t, globals.PasswordAuthMethodPrefix, got2.PublicId)
		assert.NotSame(in2, got2)
		assert.Equal(in2.Name, got2.Name)
		assert.Equal(in2.Description, got2.Description)
		assert.Equal(got2.CreateTime, got2.UpdateTime)
	})
}

func TestRepository_CreateAuthMethod_PublicId(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	t.Run("valid-with-publicid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(ctx, rw, rw, kms)
		require.NoError(err)
		require.NotNil(repo)

		org1, _ := iam.TestScopes(t, iamRepo)
		in := allocAuthMethod()

		amId, err := newAuthMethodId(ctx)
		require.NoError(err)

		in.ScopeId = org1.GetPublicId()
		got, err := repo.CreateAuthMethod(ctx, &in, WithPublicId(amId))
		require.NoError(err)
		require.NotNil(got)
		assert.Equal(amId, got.GetPublicId())
		assert.Equal(got.CreateTime, got.UpdateTime)
	})

	t.Run("invalid-with-badpublicid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(ctx, rw, rw, kms)
		require.NoError(err)
		require.NotNil(repo)

		org1, _ := iam.TestScopes(t, iamRepo)
		in := allocAuthMethod()

		in.ScopeId = org1.GetPublicId()
		got, err := repo.CreateAuthMethod(ctx, &in, WithPublicId("invalid_idwithabadprefix"))
		assert.Error(err)
		assert.Nil(got)
		assert.Truef(errors.Match(errors.T(errors.InvalidPublicId), err), "Unexpected error %s", err)
	})
}

func TestRepository_LookupAuthMethod(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	authMethod := TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]

	amId, err := newAuthMethodId(ctx)
	require.NoError(t, err)
	tests := []struct {
		name       string
		in         string
		want       *AuthMethod
		wantIsErr  errors.Code
		wantErrMsg string
	}{
		{
			name:       "With no public id",
			wantIsErr:  errors.InvalidPublicId,
			wantErrMsg: "password.(Repository).LookupAuthMethod: missing public id: parameter violation: error #102",
		},
		{
			name: "With non existing auth method id",
			in:   amId,
		},
		{
			name: "With existing auth method id",
			in:   authMethod.GetPublicId(),
			want: authMethod,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.LookupAuthMethod(ctx, tt.in)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			require.NoError(err)
			assert.EqualValues(tt.want, got)
		})
	}
}

func TestRepository_DeleteAuthMethod(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	authMethod := TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]

	newAuthMethodId, err := newAuthMethodId(ctx)
	require.NoError(t, err)
	tests := []struct {
		name       string
		in         string
		want       int
		wantIsErr  errors.Code
		wantErrMsg string
	}{
		{
			name:       "With no public id",
			wantIsErr:  errors.InvalidPublicId,
			wantErrMsg: "password.(Repository).DeleteAuthMethod: missing public id: parameter violation: error #102",
		},
		{
			name: "With non existing auth method id",
			in:   newAuthMethodId,
			want: 0,
		},
		{
			name: "With existing auth method id",
			in:   authMethod.GetPublicId(),
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
			got, err := repo.DeleteAuthMethod(ctx, o.GetPublicId(), tt.in)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			require.NoError(err)
			assert.EqualValues(tt.want, got)
		})
	}
}

func TestRepository_ListAuthMethods(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	noAuthMethodOrg, _ := iam.TestScopes(t, iamRepo)
	o, _ := iam.TestScopes(t, iamRepo)
	authMethods := TestAuthMethods(t, conn, o.GetPublicId(), 10)
	var authAMs []auth.AuthMethod
	for _, am := range authMethods {
		authAMs = append(authAMs, am)
	}

	tests := []struct {
		name       string
		in         []string
		opts       []auth.Option
		want       []auth.AuthMethod
		wantIsErr  errors.Code
		wantErrMsg string
	}{
		{
			name:       "With no scope id",
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "password.(Repository).ListAuthMethods: missing scope id: parameter violation: error #100",
		},
		{
			name: "Scope with no auth methods",
			in:   []string{noAuthMethodOrg.GetPublicId()},
			want: nil,
		},
		{
			name: "With populated scope id",
			in:   []string{o.GetPublicId()},
			want: authAMs,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.ListAuthMethods(ctx, tt.in, tt.opts...)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			require.NoError(err)
			assert.Empty(cmp.Diff(tt.want, got, protocmp.Transform()))
		})
	}
}

func TestRepository_ListAuthMethods_Multiple_Scopes(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	repo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	var total int
	const numPerScope = 10
	TestAuthMethods(t, conn, "global", numPerScope)
	total += numPerScope
	scopeIds := []string{"global"}
	for i := 0; i < 10; i++ {
		o := iam.TestOrg(t, iamRepo)
		scopeIds = append(scopeIds, o.GetPublicId())
		ams := TestAuthMethods(t, conn, o.GetPublicId(), numPerScope)
		iam.TestSetPrimaryAuthMethod(t, iam.TestRepo(t, conn, wrapper), o, ams[0].PublicId)
		total += numPerScope
	}
	got, err := repo.ListAuthMethods(ctx, scopeIds)
	require.NoError(t, err)
	assert.Equal(t, total, len(got))
	found := map[string]struct{}{}
	for _, am := range got {
		switch {
		case am.GetScopeId() == "global":
			assert.Equalf(t, false, am.GetIsPrimaryAuthMethod(), "expected the the global auth method to not be primary")
		default:
			if _, ok := found[am.GetScopeId()]; !ok {
				found[am.GetScopeId()] = struct{}{}
				assert.Equalf(t, true, am.GetIsPrimaryAuthMethod(), "expected the first auth method created for the scope %s to be primary", am.GetScopeId())
			}
		}
	}
}

func TestRepository_ListAuthMethods_Limits(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	authMethodCount := 10
	ams := TestAuthMethods(t, conn, o.GetPublicId(), authMethodCount)
	primaryAuthMethod := ams[0]
	iam.TestSetPrimaryAuthMethod(t, iam.TestRepo(t, conn, wrapper), o, primaryAuthMethod.PublicId)

	tests := []struct {
		name     string
		repoOpts []Option
		listOpts []auth.Option
		wantLen  int
	}{
		{
			name:     "With no limits",
			wantLen:  authMethodCount,
			listOpts: []auth.Option{},
		},
		{
			name:     "With repo limit",
			repoOpts: []Option{WithLimit(3)},
			listOpts: []auth.Option{},
			wantLen:  3,
		},
		{
			name:     "With negative repo limit",
			repoOpts: []Option{WithLimit(-1)},
			wantLen:  authMethodCount,
		},
		{
			name:     "With List limit",
			listOpts: []auth.Option{auth.WithLimit(ctx, 3)},
			wantLen:  3,
		},
		{
			name:     "With negative List limit",
			listOpts: []auth.Option{auth.WithLimit(ctx, -1)},
			wantLen:  authMethodCount,
		},
		{
			name:     "With repo smaller than list limit",
			repoOpts: []Option{WithLimit(2)},
			listOpts: []auth.Option{auth.WithLimit(ctx, 6)},
			wantLen:  6,
		},
		{
			name:     "With repo larger than list limit",
			repoOpts: []Option{WithLimit(6)},
			listOpts: []auth.Option{auth.WithLimit(ctx, 2)},
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
			got, err := repo.ListAuthMethods(ctx, []string{ams[0].GetScopeId()}, tt.listOpts...)
			require.NoError(err)
			assert.Len(got, tt.wantLen)
			if tt.wantLen > 0 {
				assert.Equal(true, got[0].GetIsPrimaryAuthMethod())
			}
		})
	}
}

func TestRepository_UpdateAuthMethod(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	type args struct {
		updates        *store.AuthMethod
		fieldMaskPaths []string
	}
	tests := []struct {
		name             string
		args             args
		wantRowsUpdate   int
		wantErr          bool
		skipVersionCheck bool
	}{
		{
			name: "change name",
			args: args{
				updates: &store.AuthMethod{
					Name: "updated",
				},
				fieldMaskPaths: []string{"Name"},
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "null name",
			args: args{
				updates:        &store.AuthMethod{},
				fieldMaskPaths: []string{"Name"},
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "change description",
			args: args{
				updates: &store.AuthMethod{
					Description: "updated",
				},
				fieldMaskPaths: []string{"Description"},
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "null description",
			args: args{
				updates:        &store.AuthMethod{},
				fieldMaskPaths: []string{"Description"},
			},
			wantErr:          false,
			wantRowsUpdate:   1,
			skipVersionCheck: true,
		},
		{
			name: "null name ignored description",
			args: args{
				updates:        &store.AuthMethod{Description: "ignored"},
				fieldMaskPaths: []string{"name"},
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "change min pw",
			args: args{
				updates: &store.AuthMethod{
					MinPasswordLength: 13,
				},
				fieldMaskPaths: []string{"MinPasswordLength"},
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "null min pw",
			args: args{
				updates:        &store.AuthMethod{},
				fieldMaskPaths: []string{"MinPasswordLength"},
			},
			wantErr:          false,
			wantRowsUpdate:   1,
			skipVersionCheck: true,
		},
		{
			name: "change min login name",
			args: args{
				updates: &store.AuthMethod{
					MinLoginNameLength: 13,
				},
				fieldMaskPaths: []string{"MinLoginNameLength"},
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "null min login name",
			args: args{
				updates:        &store.AuthMethod{},
				fieldMaskPaths: []string{"MinLoginNameLength"},
			},
			wantErr:          false,
			wantRowsUpdate:   1,
			skipVersionCheck: true,
		},
		{
			name: "noop update",
			args: args{
				updates: &store.AuthMethod{
					Name: "default",
				},
				fieldMaskPaths: []string{"name"},
			},
			wantErr:          false,
			wantRowsUpdate:   1,
			skipVersionCheck: true,
		},
		{
			name: "not fround",
			args: args{
				updates: &store.AuthMethod{
					PublicId: func() string {
						s, err := newAuthMethodId(ctx)
						require.NoError(t, err)
						return s
					}(),
				},
				fieldMaskPaths: []string{"name"},
			},
			wantErr:        true,
			wantRowsUpdate: 0,
		},
		{
			name: "empty field mask",
			args: args{
				updates:        &store.AuthMethod{Name: "Test"},
				fieldMaskPaths: []string{},
			},
			wantErr:        true,
			wantRowsUpdate: 0,
		},
		{
			name: "nil field mask",
			args: args{
				updates:        &store.AuthMethod{Name: "Test"},
				fieldMaskPaths: nil,
			},
			wantErr:        true,
			wantRowsUpdate: 0,
		},
		{
			name: "read-only-fields",
			args: args{
				updates:        &store.AuthMethod{Name: "Test"},
				fieldMaskPaths: []string{"CreateTime"},
			},
			wantErr:        true,
			wantRowsUpdate: 0,
		},
		{
			name: "unknown fields",
			args: args{
				updates:        &store.AuthMethod{Name: "Test"},
				fieldMaskPaths: []string{"RandomUnknownName"},
			},
			wantErr:        true,
			wantRowsUpdate: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			// create the initial auth method
			o, _ := iam.TestScopes(t, iamRepo)
			am, err := NewAuthMethod(ctx, o.GetPublicId(), WithName("default"), WithDescription("default"))
			require.NoError(err)
			origAM, err := repo.CreateAuthMethod(ctx, am)
			require.NoError(err)
			assert.EqualValues(1, origAM.Version)

			amToUpdate, err := NewAuthMethod(ctx, o.GetPublicId())
			require.NoError(err)
			amToUpdate.PublicId = origAM.GetPublicId()
			amToUpdate.Version = origAM.Version
			proto.Merge(amToUpdate.AuthMethod, tt.args.updates)
			assert.EqualValues(1, amToUpdate.Version)

			updatedAM, updatedRows, err := repo.UpdateAuthMethod(ctx, amToUpdate, amToUpdate.Version, tt.args.fieldMaskPaths)
			assert.Equal(tt.wantRowsUpdate, updatedRows)
			if tt.wantErr {
				require.Error(err)
				assert.Nil(updatedAM)
				err = db.TestVerifyOplog(t, rw, amToUpdate.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
				require.Error(err)
				assert.Contains(err.Error(), "record not found")
				return
			}
			require.NoError(err)
			if !tt.skipVersionCheck {
				assert.EqualValues(2, updatedAM.Version)
			}
			assert.NotEqual(origAM.UpdateTime, updatedAM.UpdateTime)
			foundAuthMethod, err := repo.LookupAuthMethod(ctx, origAM.PublicId)
			require.NoError(err)
			assert.Empty(cmp.Diff(updatedAM, foundAuthMethod, protocmp.Transform()))

			underlyingDB, err := conn.SqlDB(ctx)
			require.NoError(err)
			dbassert := dbassert.New(t, underlyingDB)
			if amToUpdate.Name == "" && contains(tt.args.fieldMaskPaths, "name") {
				dbassert.IsNull(foundAuthMethod, "name")
			}
			if amToUpdate.Description == "" && contains(tt.args.fieldMaskPaths, "description") {
				dbassert.IsNull(foundAuthMethod, "description")
			}

			err = db.TestVerifyOplog(t, rw, updatedAM.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
}

func TestRepository_ListAuthMethods_Pagination(t *testing.T) {
	testConn, _ := db.TestSetup(t, "postgres")
	testRw := db.New(testConn)
	testWrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, testConn, testWrapper)
	testCtx := context.Background()
	o, _ := iam.TestScopes(t, iam.TestRepo(t, testConn, testWrapper))

	TestAuthMethods(t, testConn, o.GetPublicId(), 10)

	t.Run("withStartPageAfterItem", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(testCtx, testRw, testRw, testKms)
		require.NoError(err)

		page1, err := repo.ListAuthMethods(
			context.Background(),
			[]string{o.GetPublicId()},
			auth.WithLimit(testCtx, 2),
		)
		require.NoError(err)
		require.Len(page1, 2)
		page2, err := repo.ListAuthMethods(
			context.Background(),
			[]string{o.GetPublicId()},
			auth.WithLimit(testCtx, 2),
			auth.WithStartPageAfterItem(testCtx, page1[1]),
		)
		require.NoError(err)
		require.Len(page2, 2)
		for _, item := range page1 {
			assert.NotEqual(item.GetPublicId(), page2[0].GetPublicId())
			assert.NotEqual(item.GetPublicId(), page2[1].GetPublicId())
		}
		page3, err := repo.ListAuthMethods(
			context.Background(),
			[]string{o.GetPublicId()},
			auth.WithLimit(testCtx, 2),
			auth.WithStartPageAfterItem(testCtx, page2[1]),
		)
		require.NoError(err)
		require.Len(page3, 2)
		for _, item := range page2 {
			assert.NotEqual(item.GetPublicId(), page3[0].GetPublicId())
			assert.NotEqual(item.GetPublicId(), page3[1].GetPublicId())
		}
		page4, err := repo.ListAuthMethods(
			context.Background(),
			[]string{o.GetPublicId()},
			auth.WithLimit(testCtx, 2),
			auth.WithStartPageAfterItem(testCtx, page3[1]),
		)
		require.NoError(err)
		require.Len(page4, 2)
		for _, item := range page3 {
			assert.NotEqual(item.GetPublicId(), page4[0].GetPublicId())
			assert.NotEqual(item.GetPublicId(), page4[1].GetPublicId())
		}
		page5, err := repo.ListAuthMethods(
			context.Background(),
			[]string{o.GetPublicId()},
			auth.WithLimit(testCtx, 2),
			auth.WithStartPageAfterItem(testCtx, page4[1]),
		)
		require.NoError(err)
		require.Len(page5, 2)
		for _, item := range page4 {
			assert.NotEqual(item.GetPublicId(), page5[0].GetPublicId())
			assert.NotEqual(item.GetPublicId(), page5[1].GetPublicId())
		}
		page6, err := repo.ListAuthMethods(
			context.Background(),
			[]string{o.GetPublicId()},
			auth.WithLimit(testCtx, 2),
			auth.WithStartPageAfterItem(testCtx, page5[1]),
		)
		require.NoError(err)
		require.Empty(page6)

		// Update the first target and check that it gets listed subsequently
		page1[0].(*AuthMethod).Name = "new-name"
		_, _, err = repo.UpdateAuthMethod(testCtx, page1[0].(*AuthMethod), page1[0].GetVersion(), []string{"name"})
		require.NoError(err)
		page7, err := repo.ListAuthMethods(
			context.Background(),
			[]string{o.GetPublicId()},
			auth.WithLimit(testCtx, 2),
			auth.WithStartPageAfterItem(testCtx, page5[1]),
		)
		require.NoError(err)
		require.Len(page7, 1)
		require.Equal(page7[0].GetPublicId(), page1[0].GetPublicId())
	})
}

func Test_ListDeletedAuthMethodIds(t *testing.T) {
	testConn, _ := db.TestSetup(t, "postgres")
	testRw := db.New(testConn)
	testWrapper := db.TestWrapper(t)

	ctx := context.Background()
	testKms := kms.TestKms(t, testConn, testWrapper)
	iamRepo := iam.TestRepo(t, testConn, testWrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	repo, err := NewRepository(ctx, testRw, testRw, testKms)
	assert.NoError(t, err)

	// Expect no entries at the start
	deletedIds, err := repo.ListDeletedAuthMethodIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(t, err)
	require.Empty(t, deletedIds)

	// Create and delete auth method
	authMethod := TestAuthMethod(t, testConn, org.PublicId)
	_, err = repo.DeleteAuthMethod(ctx, org.GetPublicId(), authMethod.GetPublicId())
	require.NoError(t, err)

	// Expect a single entry
	deletedIds, err = repo.ListDeletedAuthMethodIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(t, err)
	require.Equal(t, []string{authMethod.PublicId}, deletedIds)

	// Try again with the time set to now, expect no entries
	deletedIds, err = repo.ListDeletedAuthMethodIds(ctx, time.Now())
	require.NoError(t, err)
	require.Empty(t, deletedIds)
}

func Test_EstimatedAuthMethodCount(t *testing.T) {
	testConn, _ := db.TestSetup(t, "postgres")
	testRw := db.New(testConn)
	testWrapper := db.TestWrapper(t)

	testCtx := context.Background()
	sqlDb, err := testConn.SqlDB(testCtx)
	require.NoError(t, err)
	testKms := kms.TestKms(t, testConn, testWrapper)
	iamRepo := iam.TestRepo(t, testConn, testWrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	testRepo, err := NewRepository(testCtx, testRw, testRw, testKms)
	assert.NoError(t, err)

	// Check total entries at start, expect 0
	numItems, err := testRepo.EstimatedAuthMethodCount(testCtx)
	require.NoError(t, err)
	assert.Equal(t, 0, numItems)

	// Create an auth method, expect 1 entries
	authMethod := TestAuthMethod(t, testConn, org.PublicId)

	// Run analyze to update postgres meta tables
	_, err = sqlDb.ExecContext(testCtx, "analyze")
	require.NoError(t, err)

	numItems, err = testRepo.EstimatedAuthMethodCount(testCtx)
	require.NoError(t, err)
	assert.Equal(t, 1, numItems)

	// // Delete the auth method, expect 0 again
	_, err = testRepo.DeleteAuthMethod(testCtx, org.GetPublicId(), authMethod.GetPublicId())
	require.NoError(t, err)
	_, err = sqlDb.ExecContext(testCtx, "analyze")
	require.NoError(t, err)

	numItems, err = testRepo.EstimatedAuthMethodCount(testCtx)
	require.NoError(t, err)
	assert.Equal(t, 0, numItems)
}

func assertPublicId(t *testing.T, prefix, actual string) {
	t.Helper()
	assert.NotEmpty(t, actual)
	parts := strings.Split(actual, "_")
	assert.Equalf(t, 2, len(parts), "want one '_' in PublicId, got multiple in %q", actual)
	assert.Equalf(t, prefix, parts[0], "PublicId want prefix: %q, got: %q in %q", prefix, parts[0], actual)
}
