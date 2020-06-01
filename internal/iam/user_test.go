package iam

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func TestNewUser(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	assert := assert.New(t)
	defer conn.Close()
	org, _ := TestScopes(t, conn)

	id, err := uuid.GenerateUUID()
	assert.NoError(err)

	type args struct {
		organizationPublicId string
		opt                  []Option
	}
	tests := []struct {
		name       string
		args       args
		wantErr    bool
		wantErrMsg string
		wantName   string
	}{
		{
			name: "valid",
			args: args{
				organizationPublicId: org.PublicId,
				opt:                  []Option{WithName(id)},
			},
			wantErr:  false,
			wantName: id,
		},
		{
			name: "valid-with-no-name",
			args: args{
				organizationPublicId: org.PublicId,
			},
			wantErr: false,
		},
		{
			name: "no-org",
			args: args{
				opt: []Option{WithName(id)},
			},
			wantErr:    true,
			wantErrMsg: "new user: missing organization id nil parameter",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewUser(tt.args.organizationPublicId, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			assert.NoError(err)
			assert.Equal(tt.wantName, got.Name)
		})
	}
}

func Test_UserCreate(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	assert := assert.New(t)
	defer conn.Close()
	org, _ := TestScopes(t, conn)

	id, err := uuid.GenerateUUID()
	assert.NoError(err)
	t.Run("valid-user", func(t *testing.T) {
		w := db.New(conn)
		user, err := NewUser(org.PublicId)
		assert.NoError(err)
		err = w.Create(context.Background(), user)
		assert.NoError(err)
		assert.NotEmpty(user.PublicId)

		foundUser := allocUser()
		foundUser.PublicId = user.PublicId
		err = w.LookupByPublicId(context.Background(), &foundUser)
		assert.NoError(err)
		assert.Equal(user, &foundUser)
	})
	t.Run("bad-orgid", func(t *testing.T) {
		w := db.New(conn)
		user, err := NewUser(id)
		assert.NoError(err)
		err = w.Create(context.Background(), user)
		assert.Error(err)
		assert.Equal("create: vet for write failed scope is not found", err.Error())
	})
}

func Test_UserUpdate(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	a := assert.New(t)
	defer conn.Close()

	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper)
	a.NoError(err)
	id, err := uuid.GenerateUUID()
	a.NoError(err)

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
			wantErrMsg: "update: vet for write failed not allowed to change a resource's scope",
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
			wantErrMsg: `update: failed pq: duplicate key value violates unique constraint "iam_user_name_scope_id_key"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			if tt.wantDup {
				u := TestUser(t, conn, org.PublicId)
				u.Name = tt.args.name
				_, err := rw.Update(context.Background(), u, tt.args.fieldMaskPaths, nil)
				assert.NoError(err)
			}

			u := TestUser(t, conn, org.PublicId)

			updateUser := allocUser()
			updateUser.PublicId = u.PublicId
			updateUser.ScopeId = tt.args.ScopeId
			updateUser.Name = tt.args.name
			updateUser.Description = tt.args.description

			updatedRows, err := rw.Update(context.Background(), &updateUser, tt.args.fieldMaskPaths, nil)
			if tt.wantErr {
				assert.Error(err)
				assert.Equal(0, updatedRows)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			assert.NoError(err)
			assert.Equal(tt.wantRowsUpdate, updatedRows)
			assert.NotEqual(u.UpdateTime, updateUser.UpdateTime)
			foundUser, err := repo.LookupUser(context.Background(), u.PublicId)
			assert.NoError(err)
			assert.True(proto.Equal(updateUser, foundUser))
		})
	}
}

func Test_UserDelete(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	a := assert.New(t)
	defer conn.Close()

	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper)
	a.NoError(err)
	id, err := uuid.GenerateUUID()
	a.NoError(err)
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			deleteUser := allocUser()
			deleteUser.PublicId = tt.user.GetPublicId()
			deletedRows, err := rw.Delete(context.Background(), &deleteUser)
			if tt.wantRowsDeleted == 0 {
				assert.Equal(tt.wantRowsDeleted, deletedRows)
				return
			}
			assert.NoError(err)
			assert.Equal(tt.wantRowsDeleted, deletedRows)
			foundUser, err := repo.LookupUser(context.Background(), tt.user.GetPublicId())
			assert.True(errors.Is(err, db.ErrRecordNotFound))
			assert.Nil(foundUser)
		})
	}
}

func Test_UserGetScope(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	defer conn.Close()
	assert := assert.New(t)

	org, _ := TestScopes(t, conn)
	t.Run("valid-scope", func(t *testing.T) {
		w := db.New(conn)
		user, err := NewUser(org.PublicId)
		assert.NoError(err)
		err = w.Create(context.Background(), user)
		assert.NoError(err)
		assert.NotEmpty(user.PublicId)
		assert.Equal(user.ScopeId, org.PublicId)

		childScope, err := NewProject(org.PublicId)
		assert.NoError(err)
		assert.NotNil(childScope.Scope)
		assert.Equal(childScope.GetParentId(), org.PublicId)
		err = w.Create(context.Background(), childScope)
		assert.NoError(err)

		userScope, err := user.GetScope(context.Background(), w)
		assert.NoError(err)
		assert.True(proto.Equal(org, userScope))
	})

}

func TestUser_Clone(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	assert := assert.New(t)
	defer conn.Close()
	org, _ := TestScopes(t, conn)

	t.Run("valid", func(t *testing.T) {
		w := db.New(conn)
		user, err := NewUser(org.PublicId)
		assert.NoError(err)
		err = w.Create(context.Background(), user)
		assert.NoError(err)

		cp := user.Clone()
		assert.True(proto.Equal(cp.(*User).User, user.User))
	})
	t.Run("not-equal-test", func(t *testing.T) {
		w := db.New(conn)

		user, err := NewUser(org.PublicId)
		assert.NoError(err)
		err = w.Create(context.Background(), user)
		assert.NoError(err)

		user2, err := NewUser(org.PublicId)
		assert.NoError(err)
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
	assert.Equal(a[ActionCreate.String()], ActionCreate)
	assert.Equal(a[ActionUpdate.String()], ActionUpdate)
	assert.Equal(a[ActionRead.String()], ActionRead)
	assert.Equal(a[ActionDelete.String()], ActionDelete)

	if _, ok := a[ActionList.String()]; ok {
		t.Errorf("users should not include %s as an action", ActionList.String())
	}
}

func TestUser_ResourceType(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	assert := assert.New(t)
	defer conn.Close()
	org, _ := TestScopes(t, conn)

	u, err := NewUser(org.PublicId)
	assert.NoError(err)
	ty := u.ResourceType()
	assert.Equal(ty, ResourceTypeUser)
}
