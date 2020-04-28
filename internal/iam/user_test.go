package iam

import (
	"context"
	"os"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"google.golang.org/protobuf/proto"
	"gotest.tools/assert"
)

func Test_NewUser(t *testing.T) {
	db.StartTest()
	t.Parallel()
	cleanup, url := db.SetupTest(t, "../db/migrations/postgres")
	defer cleanup()
	defer db.CompleteTest() // must come after the "defer cleanup()"
	conn, err := db.TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.NilError(t, err)
		assert.Check(t, s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NilError(t, err)
		assert.Check(t, s.Id != 0)

		user, err := NewUser(s)
		assert.NilError(t, err)
		assert.Check(t, user.User != nil)
		assert.Equal(t, user.PrimaryScopeId, s.Id)
	})
}

func Test_UserCreate(t *testing.T) {
	db.StartTest()
	t.Parallel()
	cleanup, url := db.SetupTest(t, "../db/migrations/postgres")
	defer cleanup()
	defer db.CompleteTest() // must come after the "defer cleanup()"
	conn, err := db.TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()

	t.Run("valid-user", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.Equal(t, s.Type, OrganizationScope.String())
		assert.NilError(t, err)
		assert.Check(t, s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NilError(t, err)
		assert.Check(t, s.Id != 0)

		user, err := NewUser(s)
		assert.NilError(t, err)
		err = w.Create(context.Background(), user)
		assert.NilError(t, err)
		assert.Check(t, user.Id != 0)
	})
}

func Test_UserGetPrimaryScope(t *testing.T) {
	db.StartTest()
	t.Parallel()
	cleanup, url := db.SetupTest(t, "../db/migrations/postgres")
	defer cleanup()
	defer db.CompleteTest() // must come after the "defer cleanup()"
	conn, err := db.TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()
	t.Run("valid primary scope", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.NilError(t, err)
		assert.Check(t, s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NilError(t, err)
		assert.Check(t, s.Id != 0)

		user, err := NewUser(s)
		assert.NilError(t, err)
		err = w.Create(context.Background(), user)
		assert.NilError(t, err)
		assert.Check(t, user.Id != uint32(0))
		assert.Equal(t, user.PrimaryScopeId, s.Id)

		childScope, err := NewScope(ProjectScope, WithScope(s))
		assert.NilError(t, err)
		assert.Check(t, childScope.Scope != nil)
		assert.Equal(t, childScope.GetParentId(), s.Id)
		err = w.Create(context.Background(), childScope)
		assert.NilError(t, err)

		user.PrimaryScopeId = s.Id
		err = w.Update(context.Background(), user, []string{"PrimaryScopeId"})
		assert.NilError(t, err)

		primaryScope, err := user.GetPrimaryScope(context.Background(), &w)
		assert.NilError(t, err)
		assert.Check(t, primaryScope != nil)
		assert.Equal(t, primaryScope.Id, user.PrimaryScopeId)
	})

}

func Test_UserGroups(t *testing.T) {
	db.StartTest()
	t.Parallel()
	cleanup, url := db.SetupTest(t, "../db/migrations/postgres")
	defer cleanup()
	defer db.CompleteTest() // must come after the "defer cleanup()"
	conn, err := db.TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.NilError(t, err)
		assert.Check(t, s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NilError(t, err)
		assert.Check(t, s.Id != 0)

		user, err := NewUser(s)
		assert.NilError(t, err)
		err = w.Create(context.Background(), user)
		assert.NilError(t, err)

		grp, err := NewGroup(s, WithDescription("this is a test group"))
		assert.NilError(t, err)
		assert.Check(t, grp != nil)
		assert.Equal(t, grp.Description, "this is a test group")
		assert.Equal(t, s.Id, grp.PrimaryScopeId)
		err = w.Create(context.Background(), grp)
		assert.NilError(t, err)
		assert.Check(t, grp.Id != 0)

		gm, err := NewGroupMember(s, grp, user)
		assert.NilError(t, err)
		assert.Check(t, gm != nil)
		err = w.Create(context.Background(), gm)
		assert.NilError(t, err)

		group, err := user.Groups(context.Background(), &w)
		assert.NilError(t, err)
		assert.Equal(t, len(group), 1)
		assert.Equal(t, group[0].Id, grp.Id)
	})
}

func Test_UserRoles(t *testing.T) {
	db.StartTest()
	t.Parallel()
	cleanup, url := db.SetupTest(t, "../db/migrations/postgres")
	defer cleanup()
	defer db.CompleteTest() // must come after the "defer cleanup()"
	conn, err := db.TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.NilError(t, err)
		assert.Check(t, s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NilError(t, err)
		assert.Check(t, s.Id != 0)

		user, err := NewUser(s)
		assert.NilError(t, err)
		err = w.Create(context.Background(), user)
		assert.NilError(t, err)

		role, err := NewRole(s, WithDescription("this is a test role"))
		assert.NilError(t, err)
		assert.Check(t, role != nil)
		assert.Equal(t, role.Description, "this is a test role")
		assert.Equal(t, s.Id, role.PrimaryScopeId)
		err = w.Create(context.Background(), role)
		assert.NilError(t, err)
		assert.Check(t, role.Id != 0)

		uRole, err := NewAssignedRole(s, role, user)
		assert.NilError(t, err)
		assert.Check(t, uRole != nil)
		assert.Equal(t, uRole.GetRoleId(), role.Id)
		assert.Equal(t, uRole.GetPrincipalId(), user.Id)
		err = w.Create(context.Background(), uRole)
		assert.NilError(t, err)
		assert.Check(t, uRole != nil)
		assert.Equal(t, uRole.GetPrincipalId(), user.Id)

		userRoles, err := user.Roles(context.Background(), &w)
		assert.NilError(t, err)
		assert.Equal(t, len(userRoles), 1)
		assert.Equal(t, userRoles[role.PublicId].GetId(), role.Id)
	})
}

func Test_UserGrants(t *testing.T) {
	db.StartTest()
	t.Parallel()
	cleanup, url := db.SetupTest(t, "../db/migrations/postgres")
	defer cleanup()
	defer db.CompleteTest() // must come after the "defer cleanup()"
	conn, err := db.TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		if len(os.Getenv("DEBUG")) != 0 {
			// turn on debugging
			conn.LogMode(true)
		}
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.NilError(t, err)
		assert.Check(t, s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NilError(t, err)
		assert.Check(t, s.Id != 0)

		role, err := NewRole(s)
		assert.NilError(t, err)
		assert.Check(t, role != nil)
		assert.Equal(t, s.Id, role.PrimaryScopeId)
		err = w.Create(context.Background(), role)
		assert.NilError(t, err)
		assert.Check(t, role.Id != 0)

		g, err := NewRoleGrant(s, role, "everything*")
		assert.NilError(t, err)
		assert.Check(t, g != nil)
		assert.Equal(t, g.RoleId, role.Id)
		assert.Equal(t, g.Grant, "everything*")
		err = w.Create(context.Background(), g)
		assert.NilError(t, err)
		assert.Check(t, g.Id != 0)

		user, err := NewUser(s)
		assert.NilError(t, err)
		err = w.Create(context.Background(), user)
		assert.NilError(t, err)
		uRole, err := NewAssignedRole(s, role, user)
		assert.NilError(t, err)
		assert.Check(t, uRole != nil)
		assert.Equal(t, uRole.GetRoleId(), role.Id)
		assert.Equal(t, uRole.GetPrincipalId(), user.Id)
		err = w.Create(context.Background(), uRole)
		assert.NilError(t, err)
		assert.Check(t, uRole != nil)
		assert.Equal(t, uRole.GetPrincipalId(), user.Id)

		userGrants, err := user.Grants(context.Background(), &w)
		assert.NilError(t, err)
		assert.Equal(t, len(userGrants), 1)
		assert.Equal(t, userGrants[0].GetId(), g.Id)
		t.Log(userGrants)

		grp, err := NewGroup(s, WithDescription("user grants test group"))
		assert.NilError(t, err)
		assert.Check(t, grp != nil)
		assert.Equal(t, grp.Description, "user grants test group")
		assert.Equal(t, s.Id, grp.PrimaryScopeId)
		err = w.Create(context.Background(), grp)
		assert.NilError(t, err)
		assert.Check(t, grp.Id != 0)

		gm, err := NewGroupMember(s, grp, user)
		assert.NilError(t, err)
		assert.Check(t, gm != nil)
		err = w.Create(context.Background(), gm)
		assert.NilError(t, err)

		groupRole, err := NewRole(s)
		assert.NilError(t, err)
		assert.Check(t, role != nil)
		assert.Equal(t, s.Id, groupRole.PrimaryScopeId)
		err = w.Create(context.Background(), groupRole)
		assert.NilError(t, err)
		assert.Check(t, groupRole.Id != 0)

		groupGrant, err := NewRoleGrant(s, groupRole, "group-grant*")
		assert.NilError(t, err)
		assert.Check(t, groupGrant != nil)
		assert.Equal(t, groupGrant.RoleId, groupRole.Id)
		assert.Equal(t, groupGrant.Grant, "group-grant*")
		err = w.Create(context.Background(), groupGrant)
		assert.NilError(t, err)
		assert.Check(t, groupGrant.Id != 0)

		gRole, err := NewAssignedRole(s, groupRole, grp)
		assert.NilError(t, err)
		assert.Check(t, gRole != nil)
		assert.Equal(t, gRole.GetRoleId(), groupRole.Id)
		assert.Equal(t, gRole.GetPrincipalId(), grp.Id)
		err = w.Create(context.Background(), gRole)
		assert.NilError(t, err)
		assert.Check(t, gRole != nil)
		assert.Equal(t, gRole.GetPrincipalId(), grp.Id)

		allGrants, err := user.Grants(context.Background(), &w, WithGroupGrants(true))
		assert.NilError(t, err)
		assert.Equal(t, len(allGrants), 2)
		assert.Equal(t, allGrants[0].GetId(), g.Id)
		assert.Equal(t, allGrants[1].GetId(), groupGrant.Id)
		t.Log(allGrants)
	})
}
func TestUser_Clone(t *testing.T) {
	db.StartTest()
	t.Parallel()
	cleanup, url := db.SetupTest(t, "../db/migrations/postgres")
	defer cleanup()
	defer db.CompleteTest() // must come after the "defer cleanup()"
	conn, err := db.TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.NilError(t, err)
		assert.Check(t, s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NilError(t, err)
		assert.Check(t, s.Id != 0)

		user, err := NewUser(s)
		assert.NilError(t, err)
		err = w.Create(context.Background(), user)
		assert.NilError(t, err)

		cp := user.Clone()
		assert.Check(t, proto.Equal(cp.(*User).User, user.User))
	})
	t.Run("not-equal", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.NilError(t, err)
		assert.Check(t, s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NilError(t, err)
		assert.Check(t, s.Id != 0)

		user, err := NewUser(s)
		assert.NilError(t, err)
		err = w.Create(context.Background(), user)
		assert.NilError(t, err)

		user2, err := NewUser(s)
		assert.NilError(t, err)
		err = w.Create(context.Background(), user2)
		assert.NilError(t, err)

		cp := user.Clone()
		assert.Check(t, !proto.Equal(cp.(*User).User, user2.User))
	})
}
