// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam/store"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestNewUser(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	org, _ := TestScopes(t, TestRepo(t, conn, wrapper))
	id := testId(t)

	type args struct {
		orgPublicId string
		opt         []Option
	}
	tests := []struct {
		name            string
		args            args
		wantErr         bool
		wantErrMsg      string
		wantName        string
		wantDescription string
	}{
		{
			name: "valid",
			args: args{
				orgPublicId: org.PublicId,
				opt:         []Option{WithName(id), WithDescription(id)},
			},
			wantErr:         false,
			wantName:        id,
			wantDescription: id,
		},
		{
			name: "valid-with-no-name",
			args: args{
				orgPublicId: org.PublicId,
			},
			wantErr: false,
		},
		{
			name: "no-org",
			args: args{
				opt: []Option{WithName(id)},
			},
			wantErr:    true,
			wantErrMsg: "iam.NewUser: missing scope id: parameter violation: error #100",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewUser(ctx, tt.args.orgPublicId, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.Contains(err.Error(), tt.wantErrMsg)
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantName, got.Name)
			assert.Empty(got.PublicId)
		})
	}
}

func Test_UserHardcoded(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	assert, require := assert.New(t), require.New(t)
	w := db.New(conn)
	for _, v := range []string{globals.AnonymousUserId, globals.AnyAuthenticatedUserId} {
		foundUser := AllocUser()
		foundUser.PublicId = v
		err := w.LookupByPublicId(context.Background(), &foundUser)
		require.NoError(err)
		assert.Equal("global", foundUser.ScopeId)
		assert.Equal(v, foundUser.PublicId)
	}
}

func Test_UserCreate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	org, _ := TestScopes(t, TestRepo(t, conn, wrapper))
	id := testId(t)
	t.Run("valid-user", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := db.New(conn)
		user, err := NewUser(ctx, org.PublicId)
		require.NoError(err)
		id, err := newUserId(ctx)
		require.NoError(err)
		user.PublicId = id
		err = w.Create(ctx, user)
		require.NoError(err)
		require.NotEmpty(user.PublicId)

		foundUser := AllocUser()
		foundUser.PublicId = user.PublicId
		err = w.LookupByPublicId(ctx, &foundUser)
		require.NoError(err)
		assert.Equal(user, &foundUser)
	})
	t.Run("bad-orgid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := db.New(conn)
		user, err := NewUser(ctx, id)
		require.NoError(err)
		id, err := newUserId(ctx)
		require.NoError(err)
		user.PublicId = id
		err = w.Create(ctx, user)
		require.Error(err)
		assert.Equal("db.Create: dbw.Create: error before write: iam.(User).VetForWrite: iam.validateScopeForWrite: scope is not found: search issue: error #1100", err.Error())
	})
}

func Test_UserUpdate(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	id := testId(t)
	org, proj := TestScopes(t, repo)
	org2, _ := TestScopes(t, repo)

	type args struct {
		name           string
		description    string
		fieldMaskPaths []string
		ScopeId        string
		dbOpts         []db.Option
	}
	tests := []struct {
		name           string
		args           args
		wantRowsUpdate int
		wantErr        bool
		wantErrMsg     string
		wantDup        bool
	}{
		{
			name: "valid",
			args: args{
				name:           "valid" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        org.PublicId,
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "proj-scope-id",
			args: args{
				name:           "proj-scope-id" + id,
				fieldMaskPaths: []string{"ScopeId"},
				ScopeId:        proj.PublicId,
			},
			wantErr:    true,
			wantErrMsg: "db.Update: dbw.Update: error before write: iam.(User).VetForWrite: iam.validateScopeForWrite: not allowed to change a resource's scope: parameter violation: error #100",
		},
		{
			name: "proj-scope-id-not-in-mask",
			args: args{
				name:           "proj-scope-id" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        proj.PublicId,
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "empty-scope-id",
			args: args{
				name:           "empty-scope-id" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        "",
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "dup-name",
			args: args{
				name:           "dup-name" + id,
				fieldMaskPaths: []string{"Name"},
				ScopeId:        org.PublicId,
			},
			wantErr:    true,
			wantDup:    true,
			wantErrMsg: `db.Update: duplicate key value violates unique constraint "iam_user_name_scope_id_uq": unique constraint violation: integrity violation: error #1002`,
		},
		{
			name: "modified-scope",
			args: args{
				name:           "modified-scope" + id,
				fieldMaskPaths: []string{"ScopeId"},
				ScopeId:        org2.PublicId,
				dbOpts:         []db.Option{db.WithSkipVetForWrite(true)},
			},
			wantErr:    true,
			wantErrMsg: "integrity violation: error #1003",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			if tt.wantDup {
				u := TestUser(t, repo, org.PublicId)
				u.Name = tt.args.name
				_, err := rw.Update(context.Background(), u, tt.args.fieldMaskPaths, nil, tt.args.dbOpts...)
				require.NoError(err)
			}

			u := TestUser(t, repo, org.PublicId)

			updateUser := AllocUser()
			updateUser.PublicId = u.PublicId
			updateUser.ScopeId = tt.args.ScopeId
			updateUser.Name = tt.args.name
			updateUser.Description = tt.args.description

			updatedRows, err := rw.Update(context.Background(), &updateUser, tt.args.fieldMaskPaths, nil, tt.args.dbOpts...)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(0, updatedRows)
				assert.Contains(err.Error(), tt.wantErrMsg)
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantRowsUpdate, updatedRows)
			assert.NotEqual(u.UpdateTime, updateUser.UpdateTime)
			foundUser, _, err := repo.LookupUser(context.Background(), u.PublicId)
			require.NoError(err)
			assert.True(proto.Equal(updateUser, foundUser))
		})
	}
}

func Test_UserDelete(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")

	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	id := testId(t)
	org, _ := TestScopes(t, repo)

	tests := []struct {
		name            string
		user            *User
		wantRowsDeleted int
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name:            "valid",
			user:            TestUser(t, repo, org.PublicId),
			wantErr:         false,
			wantRowsDeleted: 1,
		},
		{
			name:            "bad-id",
			user:            func() *User { u := AllocUser(); u.PublicId = id; return &u }(),
			wantErr:         false,
			wantRowsDeleted: 0,
		},
		{
			name:            "anon-user",
			user:            func() *User { u := AllocUser(); u.PublicId = globals.AnonymousUserId; return &u }(),
			wantErr:         true,
			wantRowsDeleted: 0,
		},
		{
			name:            "auth-user",
			user:            func() *User { u := AllocUser(); u.PublicId = globals.AnyAuthenticatedUserId; return &u }(),
			wantErr:         true,
			wantRowsDeleted: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			deleteUser := AllocUser()
			deleteUser.PublicId = tt.user.GetPublicId()
			deletedRows, err := rw.Delete(context.Background(), &deleteUser)
			if tt.wantRowsDeleted == 0 {
				assert.Equal(tt.wantRowsDeleted, deletedRows)
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantRowsDeleted, deletedRows)
			foundUser, _, err := repo.LookupUser(context.Background(), tt.user.GetPublicId())
			assert.NoError(err)
			assert.Nil(foundUser)
		})
	}
}

func Test_UserGetScope(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, _ := TestScopes(t, repo)
	t.Run("valid-scope", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := db.New(conn)
		user := TestUser(t, repo, org.PublicId)
		userScope, err := user.GetScope(context.Background(), w)
		require.NoError(err)
		assert.True(proto.Equal(org, userScope))
	})
}

func TestUser_Clone(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, _ := TestScopes(t, repo)

	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		user := TestUser(t, repo, org.PublicId)
		cp := user.Clone()
		assert.True(proto.Equal(cp.(*User).User, user.User))
	})
	t.Run("not-equal-test", func(t *testing.T) {
		assert := assert.New(t)
		w := db.New(conn)

		user, err := NewUser(ctx, org.PublicId)
		assert.NoError(err)
		id, err := newUserId(ctx)
		assert.NoError(err)
		user.PublicId = id
		err = w.Create(ctx, user)
		assert.NoError(err)

		user2, err := NewUser(ctx, org.PublicId)
		assert.NoError(err)
		id, err = newUserId(ctx)
		assert.NoError(err)
		user2.PublicId = id
		err = w.Create(ctx, user2)
		assert.NoError(err)

		cp := user.Clone()
		assert.True(!proto.Equal(cp.(*User).User, user2.User))
	})
}

func TestUser_Actions(t *testing.T) {
	assert := assert.New(t)
	u := &User{}
	a := u.Actions()
	assert.Equal(a[action.Create.String()], action.Create)
	assert.Equal(a[action.Update.String()], action.Update)
	assert.Equal(a[action.Read.String()], action.Read)
	assert.Equal(a[action.Delete.String()], action.Delete)

	if _, ok := a[action.List.String()]; ok {
		t.Errorf("users should not include %s as an action", action.List.String())
	}
}

func TestUser_ResourceType(t *testing.T) {
	t.Parallel()
	u := AllocUser()
	assert.Equal(t, resource.User, u.GetResourceType())
}

func TestUser_SetTableName(t *testing.T) {
	defaultTableName := defaultUserTableName
	tests := []struct {
		name        string
		initialName string
		setNameTo   string
		want        string
	}{
		{
			name:        "new-name",
			initialName: "",
			setNameTo:   "new-name",
			want:        "new-name",
		},
		{
			name:        "reset to default",
			initialName: "initial",
			setNameTo:   "",
			want:        defaultTableName,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			def := AllocUser()
			require.Equal(defaultTableName, def.TableName())
			s := &User{
				User:      &store.User{},
				tableName: tt.initialName,
			}
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}
