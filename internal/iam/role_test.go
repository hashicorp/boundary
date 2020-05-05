package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func Test_NewRole(t *testing.T) {
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
		assert.True(s.PublicId != "")

		role, err := NewRole(s, WithDescription("this is a test role"))
		assert.Nil(err)
		assert.True(role != nil)
		assert.Equal(role.Description, "this is a test role")
		assert.Equal(s.PublicId, role.PrimaryScopeId)
		err = w.Create(context.Background(), role)
		assert.Nil(err)
		assert.True(role.Id != 0)
	})
	t.Run("nil-scope", func(t *testing.T) {
		role, err := NewRole(nil)
		assert.True(err != nil)
		assert.True(role == nil)
		assert.Equal(err.Error(), "error the role primary scope is nil")
	})
}

func TestRole_Actions(t *testing.T) {
	assert := assert.New(t)
	r := &Role{}
	a := r.Actions()
	assert.Equal(a[ActionList.String()], ActionList)
	assert.Equal(a[ActionCreate.String()], ActionCreate)
	assert.Equal(a[ActionUpdate.String()], ActionUpdate)
	assert.Equal(a[ActionRead.String()], ActionRead)
	assert.Equal(a[ActionDelete.String()], ActionDelete)
}

func TestRole_ResourceType(t *testing.T) {
	assert := assert.New(t)
	r := &Role{}
	ty := r.ResourceType()
	assert.Equal(ty, ResourceTypeRole)
}

func TestRole_GetPrimaryScope(t *testing.T) {
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
		assert.True(s.PublicId != "")

		role, err := NewRole(s, WithDescription("this is a test role"))
		assert.Nil(err)
		assert.True(role != nil)
		assert.Equal(role.Description, "this is a test role")
		assert.Equal(s.PublicId, role.PrimaryScopeId)
		err = w.Create(context.Background(), role)
		assert.Nil(err)
		assert.True(role.Id != 0)

		primaryScope, err := role.GetPrimaryScope(context.Background(), &w)
		assert.Nil(err)
		assert.True(primaryScope != nil)
	})
}

func TestRole_AssignedRoles(t *testing.T) {
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
		assert.True(s.PublicId != "")

		user, err := NewUser(s)
		assert.Nil(err)
		err = w.Create(context.Background(), user)
		assert.Nil(err)

		role, err := NewRole(s, WithDescription("this is a test role"))
		assert.Nil(err)
		assert.True(role != nil)
		assert.Equal(role.Description, "this is a test role")
		assert.Equal(s.PublicId, role.PrimaryScopeId)
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
		assert.Equal(s.PublicId, grp.PrimaryScopeId)
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

		allRoles, err := role.AssignedRoles(context.Background(), &w)
		assert.Nil(err)
		assert.Equal(len(allRoles), 2)
	})
}

func TestRole_Clone(t *testing.T) {
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
		assert.True(s.PublicId != "")

		role, err := NewRole(s, WithDescription("this is a test role"))
		assert.Nil(err)
		assert.True(role != nil)
		assert.Equal(role.Description, "this is a test role")
		assert.Equal(s.PublicId, role.PrimaryScopeId)
		err = w.Create(context.Background(), role)
		assert.Nil(err)
		assert.True(role.Id != 0)

		cp := role.Clone()
		assert.True(proto.Equal(cp.(*Role).Role, role.Role))
	})
	t.Run("not-equal", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		role, err := NewRole(s, WithDescription("this is a test role"))
		assert.Nil(err)
		assert.True(role != nil)
		assert.Equal(role.Description, "this is a test role")
		assert.Equal(s.PublicId, role.PrimaryScopeId)
		err = w.Create(context.Background(), role)
		assert.Nil(err)
		assert.True(role.Id != 0)

		role2, err := NewRole(s, WithDescription("this is a test role"))
		assert.Nil(err)
		assert.True(role2 != nil)
		assert.Equal(role2.Description, "this is a test role")
		assert.Equal(s.PublicId, role2.PrimaryScopeId)
		err = w.Create(context.Background(), role2)
		assert.Nil(err)
		assert.True(role2.Id != 0)

		cp := role.Clone()
		assert.True(!proto.Equal(cp.(*Role).Role, role2.Role))
	})
}
