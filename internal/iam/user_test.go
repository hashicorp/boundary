package iam

import (
	"context"
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
			wantErrMsg: "error organization id is unset for new user",
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
		assert.Equal("error on create scope is not found", err.Error())
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
	assert := assert.New(t)
	defer conn.Close()
	org, _ := TestScopes(t, conn)

	id, err := uuid.GenerateUUID()
	assert.NoError(err)
	t.Run("valid-user", func(t *testing.T) {
		w := db.New(conn)
		u := TestUser(t, conn, org.PublicId)
		u.Name = "valid-user" + id
		updatedRows, err := w.Update(context.Background(), u, []string{"Name"})
		assert.NoError(err)
		assert.Equal(1, updatedRows)

		foundUser := allocUser()
		foundUser.PublicId = u.PublicId
		err = w.LookupByPublicId(context.Background(), &foundUser)
		assert.NoError(err)
		assert.True(proto.Equal(u, foundUser))
	})
	t.Run("scope-update-not-allowed", func(t *testing.T) {
		w := db.New(conn)
		u := TestUser(t, conn, org.PublicId)

		org2, _ := TestScopes(t, conn)
		updateUser := u.Clone()
		updateUser.(*User).ScopeId = org2.PublicId
		updatedRows, err := w.Update(context.Background(), updateUser, []string{"ScopeId"})
		assert.Error(err)
		assert.Equal(0, updatedRows)
		assert.Equal("error on update not allowed to change a user's scope", err.Error())

		foundUser := allocUser()
		foundUser.PublicId = u.PublicId
		err = w.LookupByPublicId(context.Background(), &foundUser)
		assert.NoError(err)
		assert.True(proto.Equal(u, foundUser))
	})
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
		assert.True(childScope.Scope != nil)
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
