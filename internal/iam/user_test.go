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

func Test_UserGroups(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
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

		grp, err := NewGroup(org.PublicId, WithDescription("this is a test group"))
		assert.NoError(err)
		assert.NotNil(grp)
		assert.Equal(grp.Description, "this is a test group")
		assert.Equal(org.PublicId, grp.ScopeId)
		err = w.Create(context.Background(), grp)
		assert.NoError(err)
		assert.NotEqual(grp.PublicId, "")

		gm, err := NewGroupMember(grp, user)
		assert.NoError(err)
		assert.NotNil(gm)
		err = w.Create(context.Background(), gm)
		assert.NoError(err)

		group, err := user.Groups(context.Background(), w)
		assert.NoError(err)
		assert.Equal(len(group), 1)
		assert.Equal(group[0], grp)
	})
}

func Test_UserRoles(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
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

		role, err := NewRole(org.PublicId, WithDescription("this is a test role"))
		assert.NoError(err)
		assert.NotEqual(role, nil)
		assert.Equal(role.Description, "this is a test role")
		assert.Equal(org.PublicId, role.ScopeId)
		err = w.Create(context.Background(), role)
		assert.NoError(err)
		assert.NotEqual(role.PublicId, "")

		uRole, err := NewAssignedRole(role, user)
		assert.NoError(err)
		assert.True(uRole != nil)
		assert.Equal(uRole.GetRoleId(), role.PublicId)
		assert.Equal(uRole.GetPrincipalId(), user.PublicId)
		err = w.Create(context.Background(), uRole)
		assert.NoError(err)
		assert.NotNil(uRole)
		assert.Equal(uRole.GetPrincipalId(), user.PublicId)

		userRoles, err := user.Roles(context.Background(), w)
		assert.NoError(err)
		assert.Equal(len(userRoles), 1)
		assert.Equal(userRoles[role.PublicId], role)
	})
}

func Test_UserGrants(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		id, err := uuid.GenerateUUID()
		assert.NoError(err)
		w := db.New(conn)
		org, err := NewOrganization()
		assert.NoError(err)
		assert.NotNil(org.Scope)
		err = w.Create(context.Background(), org)
		assert.NoError(err)
		assert.NotEqual(org.PublicId, "")

		role, err := NewRole(org.PublicId)
		assert.NoError(err)
		assert.NotNil(role)
		assert.Equal(org.PublicId, role.ScopeId)
		err = w.Create(context.Background(), role)
		assert.NoError(err)
		assert.NotEqual(role.PublicId, "")

		g, err := NewRoleGrant(role, "everything*"+id)
		assert.NoError(err)
		assert.NotNil(g)
		assert.Equal(g.RoleId, role.PublicId)
		assert.Equal(g.Grant, "everything*"+id)
		err = w.Create(context.Background(), g)
		assert.NoError(err)
		assert.NotEqual(g.PublicId, "")

		user, err := NewUser(org.PublicId)
		assert.NoError(err)
		err = w.Create(context.Background(), user)
		assert.NoError(err)
		uRole, err := NewAssignedRole(role, user)
		assert.NoError(err)
		assert.NotNil(uRole)
		assert.Equal(uRole.GetRoleId(), role.PublicId)
		assert.Equal(uRole.GetPrincipalId(), user.PublicId)
		err = w.Create(context.Background(), uRole)
		assert.NoError(err)
		assert.NotNil(uRole)
		assert.Equal(uRole.GetPrincipalId(), user.PublicId)

		userGrants, err := user.Grants(context.Background(), w)
		assert.NoError(err)
		assert.Equal(len(userGrants), 1)
		assert.Equal(userGrants[0], g)

		grp, err := NewGroup(org.PublicId, WithDescription("user grants test group"))
		assert.NoError(err)
		assert.True(grp != nil)
		assert.Equal(grp.Description, "user grants test group")
		assert.Equal(org.PublicId, grp.ScopeId)
		err = w.Create(context.Background(), grp)
		assert.NoError(err)
		assert.NotEqual(grp.PublicId, "")

		gm, err := NewGroupMember(grp, user)
		assert.NoError(err)
		assert.NotNil(gm)
		err = w.Create(context.Background(), gm)
		assert.NoError(err)

		groupRole, err := NewRole(org.PublicId)
		assert.NoError(err)
		assert.NotNil(role)
		assert.Equal(org.PublicId, groupRole.ScopeId)
		err = w.Create(context.Background(), groupRole)
		assert.NoError(err)
		assert.NotEqual(groupRole.PublicId, "")

		groupGrant, err := NewRoleGrant(groupRole, "group-grant*"+id)
		assert.NoError(err)
		assert.True(groupGrant != nil)
		assert.Equal(groupGrant.RoleId, groupRole.PublicId)
		assert.Equal(groupGrant.Grant, "group-grant*"+id)
		err = w.Create(context.Background(), groupGrant)
		assert.NoError(err)
		assert.NotEqual(groupGrant.PublicId, "")

		gRole, err := NewAssignedRole(groupRole, grp)
		assert.NoError(err)
		assert.NotNil(gRole)
		assert.Equal(gRole.GetRoleId(), groupRole.PublicId)
		assert.Equal(gRole.GetPrincipalId(), grp.PublicId)
		err = w.Create(context.Background(), gRole)
		assert.NoError(err)
		assert.NotNil(gRole)
		assert.Equal(gRole.GetPrincipalId(), grp.PublicId)

		allGrants, err := user.Grants(context.Background(), w, WithGroupGrants(true))
		assert.NoError(err)
		assert.Equal(len(allGrants), 2)
		for _, grant := range allGrants {
			assert.True(grant.PublicId == g.PublicId || grant.PublicId == groupGrant.PublicId)
		}
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
