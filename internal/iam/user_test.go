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
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()

	w := db.New(conn)
	s, err := NewOrganization()
	assert.NoError(err)
	assert.True(s.Scope != nil)
	err = w.Create(context.Background(), s)
	assert.NoError(err)
	assert.NotEqual("", s.PublicId)

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
				organizationPublicId: s.PublicId,
				opt:                  []Option{WithName(id)},
			},
			wantErr:  false,
			wantName: id,
		},
		{
			name: "valid-with-no-name",
			args: args{
				organizationPublicId: s.PublicId,
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
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid-user", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.Equal(s.Type, OrganizationScope.String())
		assert.NoError(err)
		assert.NotNil(s.Scope)
		err = w.Create(context.Background(), s)
		assert.NoError(err)
		assert.NotEqual(s.PublicId, "")

		user, err := NewUser(s.PublicId)
		assert.NoError(err)
		err = w.Create(context.Background(), user)
		assert.NoError(err)
		assert.NotEqual(user.PublicId, "")

		foundUser := allocUser()
		foundUser.PublicId = user.PublicId
		err = w.LookupByPublicId(context.Background(), &foundUser)
		assert.NoError(err)
		assert.Equal(user, &foundUser)
	})
}

func Test_UserGetScope(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()
	t.Run("valid-scope", func(t *testing.T) {
		w := db.New(conn)
		org, err := NewOrganization()
		assert.NoError(err)
		assert.NotNil(org.Scope)
		err = w.Create(context.Background(), org)
		assert.NoError(err)
		assert.NotEqual(org.PublicId, "")

		user, err := NewUser(org.PublicId)
		assert.NoError(err)
		err = w.Create(context.Background(), user)
		assert.NoError(err)
		assert.NotEqual(user.PublicId, "")
		assert.Equal(user.ScopeId, org.PublicId)

		childScope, err := NewProject(org.PublicId)
		assert.NoError(err)
		assert.True(childScope.Scope != nil)
		assert.Equal(childScope.GetParentId(), org.PublicId)
		err = w.Create(context.Background(), childScope)
		assert.NoError(err)

		userScope, err := user.GetScope(context.Background(), w)
		assert.NoError(err)
		assert.Equal(org, userScope)
	})

}

func TestUser_Clone(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.NoError(err)
		assert.NotNil(s.Scope)
		err = w.Create(context.Background(), s)
		assert.NoError(err)
		assert.NotEqual(s.PublicId, "")

		user, err := NewUser(s.PublicId)
		assert.NoError(err)
		err = w.Create(context.Background(), user)
		assert.NoError(err)

		cp := user.Clone()
		assert.True(proto.Equal(cp.(*User).User, user.User))
	})
	t.Run("not-equal-test", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.NoError(err)
		assert.NotNil(s.Scope)
		err = w.Create(context.Background(), s)
		assert.NoError(err)
		assert.True(s.PublicId != "")

		user, err := NewUser(s.PublicId)
		assert.NoError(err)
		err = w.Create(context.Background(), user)
		assert.NoError(err)

		user2, err := NewUser(s.PublicId)
		assert.NoError(err)
		err = w.Create(context.Background(), user2)
		assert.NoError(err)

		cp := user.Clone()
		assert.True(!proto.Equal(cp.(*User).User, user2.User))
	})
}
