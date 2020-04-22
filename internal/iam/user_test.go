package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
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
		assert.Equal(t, s.Type, uint32(OrganizationScope))
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
	})
}
