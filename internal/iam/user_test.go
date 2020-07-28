package iam

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam/store"
	"github.com/hashicorp/watchtower/internal/types/action"
	"github.com/hashicorp/watchtower/internal/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestNewUser(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	org, _ := TestScopes(t, conn)
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
			wantErrMsg: "new user: missing scope id invalid parameter",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewUser(tt.args.orgPublicId, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(tt.wantErrMsg, err.Error())
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
	for _, v := range []string{"u_anon", "u_auth"} {
		foundUser := allocUser()
		foundUser.PublicId = v
		err := w.LookupByPublicId(context.Background(), &foundUser)
		require.NoError(err)
		assert.Equal("global", foundUser.ScopeId)
		assert.Equal(v, foundUser.PublicId)
	}
}

func Test_UserCreate(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	org, _ := TestScopes(t, conn)
	id := testId(t)
	t.Run("valid-user", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := db.New(conn)
		user, err := NewUser(org.PublicId)
		require.NoError(err)
		id, err := newUserId()
		require.NoError(err)
		user.PublicId = id
		err = w.Create(context.Background(), user)
		require.NoError(err)
		require.NotEmpty(user.PublicId)

		foundUser := allocUser()
		foundUser.PublicId = user.PublicId
		err = w.LookupByPublicId(context.Background(), &foundUser)
		require.NoError(err)
		assert.Equal(user, &foundUser)
	})
	t.Run("bad-orgid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := db.New(conn)
		user, err := NewUser(id)
		require.NoError(err)
		id, err := newUserId()
		require.NoError(err)
		user.PublicId = id
		err = w.Create(context.Background(), user)
		require.Error(err)
		assert.Equal("create: vet for write failed: scope is not found", err.Error())
	})
	t.Run("bad-scope", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := db.New(conn)
		user, err := NewUser("global")
		require.NoError(err)
		id, err := newUserId()
		require.NoError(err)
		user.PublicId = id
		err = w.Create(context.Background(), user)
		require.Error(err)
		assert.Equal("create: vet for write failed: global not a valid scope type for this resource", err.Error())
	})
}

func Test_UserUpdate(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper)
	require.NoError(t, err)
	id := testId(t)
	org, proj := TestScopes(t, conn)

	type args struct {
		name           string
		description    string
		fieldMaskPaths []string
		ScopeId        string
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
			wantErrMsg: "update: vet for write failed: not allowed to change a resource's scope",
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
			wantErrMsg: `update: failed: pq: duplicate key value violates unique constraint "iam_user_name_scope_id_key"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			if tt.wantDup {
				u := TestUser(t, conn, org.PublicId)
				u.Name = tt.args.name
				_, err := rw.Update(context.Background(), u, tt.args.fieldMaskPaths, nil)
				require.NoError(err)
			}

			u := TestUser(t, conn, org.PublicId)

			updateUser := allocUser()
			updateUser.PublicId = u.PublicId
			updateUser.ScopeId = tt.args.ScopeId
			updateUser.Name = tt.args.name
			updateUser.Description = tt.args.description

			updatedRows, err := rw.Update(context.Background(), &updateUser, tt.args.fieldMaskPaths, nil)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(0, updatedRows)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantRowsUpdate, updatedRows)
			assert.NotEqual(u.UpdateTime, updateUser.UpdateTime)
			foundUser, err := repo.LookupUser(context.Background(), u.PublicId)
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
	repo, err := NewRepository(rw, rw, wrapper)
	require.NoError(t, err)
	id := testId(t)
	org, _ := TestScopes(t, conn)

	tests := []struct {
		name            string
		user            *User
		wantRowsDeleted int
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name:            "valid",
			user:            TestUser(t, conn, org.PublicId),
			wantErr:         false,
			wantRowsDeleted: 1,
		},
		{
			name:            "bad-id",
			user:            func() *User { u := allocUser(); u.PublicId = id; return &u }(),
			wantErr:         false,
			wantRowsDeleted: 0,
		},
		{
			name:            "anon-user",
			user:            func() *User { u := allocUser(); u.PublicId = "u_anon"; return &u }(),
			wantErr:         true,
			wantRowsDeleted: 0,
		},
		{
			name:            "auth-user",
			user:            func() *User { u := allocUser(); u.PublicId = "u_auth"; return &u }(),
			wantErr:         true,
			wantRowsDeleted: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			deleteUser := allocUser()
			deleteUser.PublicId = tt.user.GetPublicId()
			deletedRows, err := rw.Delete(context.Background(), &deleteUser)
			if tt.wantRowsDeleted == 0 {
				assert.Equal(tt.wantRowsDeleted, deletedRows)
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantRowsDeleted, deletedRows)
			foundUser, err := repo.LookupUser(context.Background(), tt.user.GetPublicId())
			assert.True(errors.Is(err, db.ErrRecordNotFound))
			assert.Nil(foundUser)
		})
	}
}

func Test_UserGetScope(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	org, _ := TestScopes(t, conn)
	t.Run("valid-scope", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := db.New(conn)
		user := TestUser(t, conn, org.PublicId)
		userScope, err := user.GetScope(context.Background(), w)
		require.NoError(err)
		assert.True(proto.Equal(org, userScope))
	})

}

func TestUser_Clone(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	org, _ := TestScopes(t, conn)

	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		user := TestUser(t, conn, org.PublicId)
		cp := user.Clone()
		assert.True(proto.Equal(cp.(*User).User, user.User))
	})
	t.Run("not-equal-test", func(t *testing.T) {
		assert := assert.New(t)
		w := db.New(conn)

		user, err := NewUser(org.PublicId)
		assert.NoError(err)
		id, err := newUserId()
		assert.NoError(err)
		user.PublicId = id
		err = w.Create(context.Background(), user)
		assert.NoError(err)

		user2, err := NewUser(org.PublicId)
		assert.NoError(err)
		id, err = newUserId()
		assert.NoError(err)
		user2.PublicId = id
		err = w.Create(context.Background(), user2)
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
	u := allocUser()
	assert.Equal(t, resource.User, u.ResourceType())
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
			def := allocUser()
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
