package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
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
	assert := assert.New(t)
	assert.Nil(err)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.Id != 0)

		user, err := NewUser(s)
		assert.Nil(err)
		err = w.Create(context.Background(), user)
		assert.Nil(err)

		role, err := NewRole(s, WithDescription("this is a test role"))
		assert.Nil(err)
		assert.True(role != nil)
		assert.Equal(role.Description, "this is a test role")
		assert.Equal(s.Id, role.PrimaryScopeId)
		err = w.Create(context.Background(), role)
		assert.Nil(err)
		assert.True(role.Id != 0)

		uRole, err := NewAssignedRole(s, role, user)
		assert.Nil(err)
		assert.True(uRole != nil)
		assert.Equal(uRole.GetRoleId(), role.Id)
		assert.Equal(uRole.GetPrincipalId(), user.Id)
		err = w.Create(context.Background(), uRole)
		assert.Nil(err)
		assert.True(uRole != nil)
		assert.Equal(uRole.GetPrincipalId(), user.Id)

		grp, err := NewGroup(s, WithDescription("this is a test group"))
		assert.Nil(err)
		assert.True(grp != nil)
		assert.Equal(grp.Description, "this is a test group")
		assert.Equal(s.Id, grp.PrimaryScopeId)
		err = w.Create(context.Background(), grp)
		assert.Nil(err)
		assert.True(grp.Id != 0)

		gRole, err := NewAssignedRole(s, role, grp)
		assert.Nil(err)
		assert.True(gRole != nil)
		assert.Equal(gRole.GetRoleId(), role.Id)
		assert.Equal(gRole.GetPrincipalId(), grp.Id)
		err = w.Create(context.Background(), gRole)
		assert.Nil(err)
		assert.True(gRole != nil)
		assert.Equal(gRole.GetPrincipalId(), grp.Id)
	})
	t.Run("bad-resource-type", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.Id != 0)

		secondScope, err := NewScope(OrganizationScope)
		assert.Nil(err)
		assert.True(secondScope.Scope != nil)
		err = w.Create(context.Background(), secondScope)
		assert.Nil(err)
		assert.True(secondScope.Id != 0)

		role, err := NewRole(s, WithDescription("this is a test role"))
		assert.Nil(err)
		assert.True(role != nil)
		assert.Equal(role.Description, "this is a test role")
		assert.Equal(s.Id, role.PrimaryScopeId)
		err = w.Create(context.Background(), role)
		assert.Nil(err)
		assert.True(role.Id != 0)

		uRole, err := NewAssignedRole(s, role, secondScope)
		assert.True(err != nil)
		assert.True(uRole == nil)
		assert.Equal(err.Error(), "error unknown principal type for assigning role")
	})
	t.Run("nil-role", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.Id != 0)

		user, err := NewUser(s)
		assert.Nil(err)
		err = w.Create(context.Background(), user)
		assert.Nil(err)

		uRole, err := NewAssignedRole(s, nil, user)
		assert.True(err != nil)
		assert.True(uRole == nil)
		assert.Equal(err.Error(), "error role is nil for assigning role")
	})
	t.Run("nil-principal", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.Id != 0)

		role, err := NewRole(s, WithDescription("this is a test role"))
		assert.Nil(err)
		assert.True(role != nil)
		assert.Equal(role.Description, "this is a test role")
		assert.Equal(s.Id, role.PrimaryScopeId)
		err = w.Create(context.Background(), role)
		assert.Nil(err)
		assert.True(role.Id != 0)

		uRole, err := NewAssignedRole(s, role, nil)
		assert.True(err != nil)
		assert.True(uRole == nil)
		assert.Equal(err.Error(), "principal is nil for assigning role")
	})
	t.Run("nil-scope", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.Id != 0)

		role, err := NewRole(s, WithDescription("this is a test role"))
		assert.Nil(err)
		assert.True(role != nil)
		assert.Equal(role.Description, "this is a test role")
		assert.Equal(s.Id, role.PrimaryScopeId)
		err = w.Create(context.Background(), role)
		assert.Nil(err)
		assert.True(role.Id != 0)

		user, err := NewUser(s)
		assert.Nil(err)
		err = w.Create(context.Background(), user)
		assert.Nil(err)

		uRole, err := NewAssignedRole(nil, role, user)
		assert.True(err != nil)
		assert.True(uRole == nil)
		assert.Equal(err.Error(), "error scope is nil for assigning role")
	})
}

func TestUserRole_GetPrimaryScope(t *testing.T) {
	db.StartTest()
	t.Parallel()
	cleanup, url := db.SetupTest(t, "../db/migrations/postgres")
	defer cleanup()
	defer db.CompleteTest() // must come after the "defer cleanup()"
	conn, err := db.TestConnection(url)
	assert := assert.New(t)
	assert.Nil(err)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.Id != 0)

		user, err := NewUser(s)
		assert.Nil(err)
		err = w.Create(context.Background(), user)
		assert.Nil(err)

		role, err := NewRole(s, WithDescription("this is a test role"))
		assert.Nil(err)
		assert.True(role != nil)
		assert.Equal(role.Description, "this is a test role")
		assert.Equal(s.Id, role.PrimaryScopeId)
		err = w.Create(context.Background(), role)
		assert.Nil(err)
		assert.True(role.Id != 0)

		uRole, err := NewAssignedRole(s, role, user)
		assert.Nil(err)
		assert.True(uRole != nil)
		assert.Equal(uRole.GetRoleId(), role.Id)
		assert.Equal(uRole.GetPrincipalId(), user.Id)
		err = w.Create(context.Background(), uRole)
		assert.Nil(err)
		assert.True(uRole != nil)
		assert.Equal(uRole.GetPrincipalId(), user.Id)

		primaryScope, err := uRole.GetPrimaryScope(context.Background(), &w)
		assert.Nil(err)
		assert.True(primaryScope != nil)
	})
}

func TestUserRole_Actions(t *testing.T) {
	assert := assert.New(t)
	r := &UserRole{}
	a := r.Actions()
	assert.Equal(a[ActionList.String()], ActionList)
	assert.Equal(a[ActionCreate.String()], ActionCreate)
	assert.Equal(a[ActionUpdate.String()], ActionUpdate)
	assert.Equal(a[ActionRead.String()], ActionRead)
	assert.Equal(a[ActionDelete.String()], ActionDelete)
}

func TestGroupRole_Actions(t *testing.T) {
	assert := assert.New(t)
	r := &GroupRole{}
	a := r.Actions()
	assert.Equal(a[ActionList.String()], ActionList)
	assert.Equal(a[ActionCreate.String()], ActionCreate)
	assert.Equal(a[ActionUpdate.String()], ActionUpdate)
	assert.Equal(a[ActionRead.String()], ActionRead)
	assert.Equal(a[ActionDelete.String()], ActionDelete)
}

func TestGroupRole_GetPrimaryScope(t *testing.T) {
	db.StartTest()
	t.Parallel()
	cleanup, url := db.SetupTest(t, "../db/migrations/postgres")
	defer cleanup()
	defer db.CompleteTest() // must come after the "defer cleanup()"
	conn, err := db.TestConnection(url)
	assert := assert.New(t)
	assert.Nil(err)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.Id != 0)

		role, err := NewRole(s, WithDescription("this is a test role"))
		assert.Nil(err)
		assert.True(role != nil)
		assert.Equal(role.Description, "this is a test role")
		assert.Equal(s.Id, role.PrimaryScopeId)
		err = w.Create(context.Background(), role)
		assert.Nil(err)
		assert.True(role.Id != 0)

		grp, err := NewGroup(s, WithDescription("this is a test group"))
		assert.Nil(err)
		assert.True(grp != nil)
		assert.Equal(grp.Description, "this is a test group")
		assert.Equal(s.Id, grp.PrimaryScopeId)
		err = w.Create(context.Background(), grp)
		assert.Nil(err)
		assert.True(grp.Id != 0)

		gRole, err := NewAssignedRole(s, role, grp)
		assert.Nil(err)
		assert.True(gRole != nil)
		assert.Equal(gRole.GetRoleId(), role.Id)
		assert.Equal(gRole.GetPrincipalId(), grp.Id)
		err = w.Create(context.Background(), gRole)
		assert.Nil(err)
		assert.True(gRole != nil)
		assert.Equal(gRole.GetPrincipalId(), grp.Id)

		primaryScope, err := gRole.GetPrimaryScope(context.Background(), &w)
		assert.Nil(err)
		assert.True(primaryScope != nil)
	})
}
