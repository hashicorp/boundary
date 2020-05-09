package iam

import (
	"context"
	"os"
	"testing"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func Test_NewUser(t *testing.T) {
	t.Parallel()
	cleanup, conn := db.TestSetup(t, "../db/migrations/postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewOrganization()
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		user, err := NewUser(s)
		assert.Nil(err)
		assert.True(user.User != nil)
		assert.Equal(user.ScopeId, s.PublicId)
	})
}

func Test_UserCreate(t *testing.T) {
	t.Parallel()
	cleanup, conn := db.TestSetup(t, "../db/migrations/postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid-user", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewOrganization()
		assert.Equal(s.Type, OrganizationScope.String())
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		user, err := NewUser(s)
		assert.Nil(err)
		err = w.Create(context.Background(), user)
		assert.Nil(err)
		assert.True(user.PublicId != "")
	})
}

func Test_UserGetScope(t *testing.T) {
	t.Parallel()
	cleanup, conn := db.TestSetup(t, "../db/migrations/postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()
	t.Run("valid scope", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewOrganization()
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		user, err := NewUser(s)
		assert.Nil(err)
		err = w.Create(context.Background(), user)
		assert.Nil(err)
		assert.True(user.PublicId != "")
		assert.Equal(user.ScopeId, s.PublicId)

		childScope, err := NewProject(s.PublicId)
		assert.Nil(err)
		assert.True(childScope.Scope != nil)
		assert.Equal(childScope.GetParentId(), s.PublicId)
		err = w.Create(context.Background(), childScope)
		assert.Nil(err)

		user.ScopeId = s.PublicId
		err = w.Update(context.Background(), user, []string{"ScopeId"})
		assert.Nil(err)

		scope, err := user.GetScope(context.Background(), &w)
		assert.Nil(err)
		assert.True(scope != nil)
		assert.Equal(scope.PublicId, user.ScopeId)
	})

}

func Test_UserGroups(t *testing.T) {
	t.Parallel()
	cleanup, conn := db.TestSetup(t, "../db/migrations/postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewOrganization()
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		user, err := NewUser(s)
		assert.Nil(err)
		err = w.Create(context.Background(), user)
		assert.Nil(err)

		grp, err := NewGroup(s, WithDescription("this is a test group"))
		assert.Nil(err)
		assert.True(grp != nil)
		assert.Equal(grp.Description, "this is a test group")
		assert.Equal(s.PublicId, grp.ScopeId)
		err = w.Create(context.Background(), grp)
		assert.Nil(err)
		assert.True(grp.PublicId != "")

		gm, err := NewGroupMember(grp, user)
		assert.Nil(err)
		assert.True(gm != nil)
		err = w.Create(context.Background(), gm)
		assert.Nil(err)

		group, err := user.Groups(context.Background(), &w)
		assert.Nil(err)
		assert.Equal(len(group), 1)
		assert.Equal(group[0].PublicId, grp.PublicId)
	})
}

func Test_UserRoles(t *testing.T) {
	t.Parallel()
	cleanup, conn := db.TestSetup(t, "../db/migrations/postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewOrganization()
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		user, err := NewUser(s)
		assert.Nil(err)
		err = w.Create(context.Background(), user)
		assert.Nil(err)

		role, err := NewRole(s, WithDescription("this is a test role"))
		assert.Nil(err)
		assert.True(role != nil)
		assert.Equal(role.Description, "this is a test role")
		assert.Equal(s.PublicId, role.ScopeId)
		err = w.Create(context.Background(), role)
		assert.Nil(err)
		assert.True(role.PublicId != "")

		uRole, err := NewAssignedRole(s, role, user)
		assert.Nil(err)
		assert.True(uRole != nil)
		assert.Equal(uRole.GetRoleId(), role.PublicId)
		assert.Equal(uRole.GetPrincipalId(), user.PublicId)
		err = w.Create(context.Background(), uRole)
		assert.Nil(err)
		assert.True(uRole != nil)
		assert.Equal(uRole.GetPrincipalId(), user.PublicId)

		userRoles, err := user.Roles(context.Background(), &w)
		assert.Nil(err)
		assert.Equal(len(userRoles), 1)
		assert.Equal(userRoles[role.PublicId].GetPublicId(), role.PublicId)
	})
}

func Test_UserGrants(t *testing.T) {
	t.Parallel()
	cleanup, conn := db.TestSetup(t, "../db/migrations/postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		if len(os.Getenv("DEBUG")) != 0 {
			// turn on debugging
			conn.LogMode(true)
		}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)
		w := db.GormReadWriter{Tx: conn}
		s, err := NewOrganization()
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		role, err := NewRole(s)
		assert.Nil(err)
		assert.True(role != nil)
		assert.Equal(s.PublicId, role.ScopeId)
		err = w.Create(context.Background(), role)
		assert.Nil(err)
		assert.True(role.PublicId != "")

		g, err := NewRoleGrant(s, role, "everything*"+id)
		assert.Nil(err)
		assert.True(g != nil)
		assert.Equal(g.RoleId, role.PublicId)
		assert.Equal(g.Grant, "everything*"+id)
		err = w.Create(context.Background(), g)
		assert.Nil(err)
		assert.True(g.PublicId != "")

		user, err := NewUser(s)
		assert.Nil(err)
		err = w.Create(context.Background(), user)
		assert.Nil(err)
		uRole, err := NewAssignedRole(s, role, user)
		assert.Nil(err)
		assert.True(uRole != nil)
		assert.Equal(uRole.GetRoleId(), role.PublicId)
		assert.Equal(uRole.GetPrincipalId(), user.PublicId)
		err = w.Create(context.Background(), uRole)
		assert.Nil(err)
		assert.True(uRole != nil)
		assert.Equal(uRole.GetPrincipalId(), user.PublicId)

		userGrants, err := user.Grants(context.Background(), &w)
		assert.Nil(err)
		assert.Equal(len(userGrants), 1)
		assert.Equal(userGrants[0].GetPublicId(), g.PublicId)

		grp, err := NewGroup(s, WithDescription("user grants test group"))
		assert.Nil(err)
		assert.True(grp != nil)
		assert.Equal(grp.Description, "user grants test group")
		assert.Equal(s.PublicId, grp.ScopeId)
		err = w.Create(context.Background(), grp)
		assert.Nil(err)
		assert.True(grp.PublicId != "")

		gm, err := NewGroupMember(grp, user)
		assert.Nil(err)
		assert.True(gm != nil)
		err = w.Create(context.Background(), gm)
		assert.Nil(err)

		groupRole, err := NewRole(s)
		assert.Nil(err)
		assert.True(role != nil)
		assert.Equal(s.PublicId, groupRole.ScopeId)
		err = w.Create(context.Background(), groupRole)
		assert.Nil(err)
		assert.True(groupRole.PublicId != "")

		groupGrant, err := NewRoleGrant(s, groupRole, "group-grant*"+id)
		assert.Nil(err)
		assert.True(groupGrant != nil)
		assert.Equal(groupGrant.RoleId, groupRole.PublicId)
		assert.Equal(groupGrant.Grant, "group-grant*"+id)
		err = w.Create(context.Background(), groupGrant)
		assert.Nil(err)
		assert.True(groupGrant.PublicId != "")

		gRole, err := NewAssignedRole(s, groupRole, grp)
		assert.Nil(err)
		assert.True(gRole != nil)
		assert.Equal(gRole.GetRoleId(), groupRole.PublicId)
		assert.Equal(gRole.GetPrincipalId(), grp.PublicId)
		err = w.Create(context.Background(), gRole)
		assert.Nil(err)
		assert.True(gRole != nil)
		assert.Equal(gRole.GetPrincipalId(), grp.PublicId)

		allGrants, err := user.Grants(context.Background(), &w, WithGroupGrants(true))
		assert.Nil(err)
		assert.Equal(len(allGrants), 2)
		for _, grant := range allGrants {
			assert.True(grant.PublicId == g.PublicId || grant.PublicId == groupGrant.PublicId)
		}
	})
}
func TestUser_Clone(t *testing.T) {
	t.Parallel()
	cleanup, conn := db.TestSetup(t, "../db/migrations/postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewOrganization()
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		user, err := NewUser(s)
		assert.Nil(err)
		err = w.Create(context.Background(), user)
		assert.Nil(err)

		cp := user.Clone()
		assert.True(proto.Equal(cp.(*User).User, user.User))
	})
	t.Run("not-equal", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewOrganization()
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		user, err := NewUser(s)
		assert.Nil(err)
		err = w.Create(context.Background(), user)
		assert.Nil(err)

		user2, err := NewUser(s)
		assert.Nil(err)
		err = w.Create(context.Background(), user2)
		assert.Nil(err)

		cp := user.Clone()
		assert.True(!proto.Equal(cp.(*User).User, user2.User))
	})
}
