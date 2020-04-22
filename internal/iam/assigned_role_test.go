package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"gotest.tools/assert"
)

// Test_NewAssignedRole provides unit tests for NewAssignedRole() which
// is the preferred way to assign roles to users and groups
func Test_NewAssignedRole(t *testing.T) {
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

		grp, err := NewGroup(s, WithDescription("this is a test group"))
		assert.NilError(t, err)
		assert.Check(t, grp != nil)
		assert.Equal(t, grp.Description, "this is a test group")
		assert.Equal(t, s.Id, grp.PrimaryScopeId)
		err = w.Create(context.Background(), grp)
		assert.NilError(t, err)
		assert.Check(t, grp.Id != 0)

		gRole, err := NewAssignedRole(s, role, grp)
		assert.NilError(t, err)
		assert.Check(t, gRole != nil)
		assert.Equal(t, gRole.GetRoleId(), role.Id)
		assert.Equal(t, gRole.GetPrincipalId(), grp.Id)
		err = w.Create(context.Background(), gRole)
		assert.NilError(t, err)
		assert.Check(t, gRole != nil)
		assert.Equal(t, gRole.GetPrincipalId(), grp.Id)
	})
	t.Run("bad-resource-type", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.NilError(t, err)
		assert.Check(t, s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NilError(t, err)
		assert.Check(t, s.Id != 0)

		secondScope, err := NewScope(OrganizationScope)
		assert.NilError(t, err)
		assert.Check(t, secondScope.Scope != nil)
		err = w.Create(context.Background(), secondScope)
		assert.NilError(t, err)
		assert.Check(t, secondScope.Id != 0)

		role, err := NewRole(s, WithDescription("this is a test role"))
		assert.NilError(t, err)
		assert.Check(t, role != nil)
		assert.Equal(t, role.Description, "this is a test role")
		assert.Equal(t, s.Id, role.PrimaryScopeId)
		err = w.Create(context.Background(), role)
		assert.NilError(t, err)
		assert.Check(t, role.Id != 0)

		uRole, err := NewAssignedRole(s, role, secondScope)
		assert.Check(t, err != nil)
		assert.Check(t, uRole == nil)
		assert.Equal(t, err.Error(), "error unknown principal type for assigning role")
	})
	t.Run("nil-role", func(t *testing.T) {
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

		uRole, err := NewAssignedRole(s, nil, user)
		assert.Check(t, err != nil)
		assert.Check(t, uRole == nil)
		assert.Equal(t, err.Error(), "error role is nil for assigning role")
	})
	t.Run("nil-principal", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.NilError(t, err)
		assert.Check(t, s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NilError(t, err)
		assert.Check(t, s.Id != 0)

		role, err := NewRole(s, WithDescription("this is a test role"))
		assert.NilError(t, err)
		assert.Check(t, role != nil)
		assert.Equal(t, role.Description, "this is a test role")
		assert.Equal(t, s.Id, role.PrimaryScopeId)
		err = w.Create(context.Background(), role)
		assert.NilError(t, err)
		assert.Check(t, role.Id != 0)

		uRole, err := NewAssignedRole(s, role, nil)
		assert.Check(t, err != nil)
		assert.Check(t, uRole == nil)
		assert.Equal(t, err.Error(), "principal is nil for assigning role")
	})
	t.Run("nil-scope", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.NilError(t, err)
		assert.Check(t, s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NilError(t, err)
		assert.Check(t, s.Id != 0)

		role, err := NewRole(s, WithDescription("this is a test role"))
		assert.NilError(t, err)
		assert.Check(t, role != nil)
		assert.Equal(t, role.Description, "this is a test role")
		assert.Equal(t, s.Id, role.PrimaryScopeId)
		err = w.Create(context.Background(), role)
		assert.NilError(t, err)
		assert.Check(t, role.Id != 0)

		user, err := NewUser(s)
		assert.NilError(t, err)
		err = w.Create(context.Background(), user)
		assert.NilError(t, err)

		uRole, err := NewAssignedRole(nil, role, user)
		assert.Check(t, err != nil)
		assert.Check(t, uRole == nil)
		assert.Equal(t, err.Error(), "error scope is nil for assigning role")
	})
}

func TestUserRole_GetPrimaryScope(t *testing.T) {
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

		primaryScope, err := uRole.GetPrimaryScope(context.Background(), &w)
		assert.NilError(t, err)
		assert.Check(t, primaryScope != nil)
	})
}

func TestUserRole_Actions(t *testing.T) {
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

		a := uRole.Actions()
		assert.NilError(t, err)
		assert.Equal(t, a[ActionList.String()], ActionList)
		assert.Equal(t, a[ActionCreate.String()], ActionCreate)
		assert.Equal(t, a[ActionUpdate.String()], ActionUpdate)
		assert.Equal(t, a[ActionEdit.String()], ActionEdit)
		assert.Equal(t, a[ActionDelete.String()], ActionDelete)
	})
}

func TestGroupRole_Actions(t *testing.T) {
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

		role, err := NewRole(s, WithDescription("this is a test role"))
		assert.NilError(t, err)
		assert.Check(t, role != nil)
		assert.Equal(t, role.Description, "this is a test role")
		assert.Equal(t, s.Id, role.PrimaryScopeId)
		err = w.Create(context.Background(), role)
		assert.NilError(t, err)
		assert.Check(t, role.Id != 0)

		grp, err := NewGroup(s, WithDescription("this is a test group"))
		assert.NilError(t, err)
		assert.Check(t, grp != nil)
		assert.Equal(t, grp.Description, "this is a test group")
		assert.Equal(t, s.Id, grp.PrimaryScopeId)
		err = w.Create(context.Background(), grp)
		assert.NilError(t, err)
		assert.Check(t, grp.Id != 0)

		gRole, err := NewAssignedRole(s, role, grp)
		assert.NilError(t, err)
		assert.Check(t, gRole != nil)
		assert.Equal(t, gRole.GetRoleId(), role.Id)
		assert.Equal(t, gRole.GetPrincipalId(), grp.Id)
		err = w.Create(context.Background(), gRole)
		assert.NilError(t, err)
		assert.Check(t, gRole != nil)
		assert.Equal(t, gRole.GetPrincipalId(), grp.Id)

		a := gRole.Actions()
		assert.NilError(t, err)
		assert.Equal(t, a[ActionList.String()], ActionList)
		assert.Equal(t, a[ActionCreate.String()], ActionCreate)
		assert.Equal(t, a[ActionUpdate.String()], ActionUpdate)
		assert.Equal(t, a[ActionEdit.String()], ActionEdit)
		assert.Equal(t, a[ActionDelete.String()], ActionDelete)
	})
}

func TestGroupRole_GetPrimaryScope(t *testing.T) {
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

		role, err := NewRole(s, WithDescription("this is a test role"))
		assert.NilError(t, err)
		assert.Check(t, role != nil)
		assert.Equal(t, role.Description, "this is a test role")
		assert.Equal(t, s.Id, role.PrimaryScopeId)
		err = w.Create(context.Background(), role)
		assert.NilError(t, err)
		assert.Check(t, role.Id != 0)

		grp, err := NewGroup(s, WithDescription("this is a test group"))
		assert.NilError(t, err)
		assert.Check(t, grp != nil)
		assert.Equal(t, grp.Description, "this is a test group")
		assert.Equal(t, s.Id, grp.PrimaryScopeId)
		err = w.Create(context.Background(), grp)
		assert.NilError(t, err)
		assert.Check(t, grp.Id != 0)

		gRole, err := NewAssignedRole(s, role, grp)
		assert.NilError(t, err)
		assert.Check(t, gRole != nil)
		assert.Equal(t, gRole.GetRoleId(), role.Id)
		assert.Equal(t, gRole.GetPrincipalId(), grp.Id)
		err = w.Create(context.Background(), gRole)
		assert.NilError(t, err)
		assert.Check(t, gRole != nil)
		assert.Equal(t, gRole.GetPrincipalId(), grp.Id)

		primaryScope, err := gRole.GetPrimaryScope(context.Background(), &w)
		assert.NilError(t, err)
		assert.Check(t, primaryScope != nil)
	})
}
