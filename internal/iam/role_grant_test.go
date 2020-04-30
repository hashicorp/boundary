package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func TestNewRoleGrant(t *testing.T) {

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

		role, err := NewRole(s)
		assert.Nil(err)
		assert.True(role != nil)
		assert.Equal(s.Id, role.PrimaryScopeId)
		err = w.Create(context.Background(), role)
		assert.Nil(err)
		assert.True(role.Id != 0)

		g, err := NewRoleGrant(s, role, "everything*")
		assert.Nil(err)
		assert.True(g != nil)
		assert.Equal(g.RoleId, role.Id)
		assert.Equal(g.Grant, "everything*")
		err = w.Create(context.Background(), g)
		assert.Nil(err)
		assert.True(g.Id != 0)

		user, err := NewUser(s)
		assert.Nil(err)
		err = w.Create(context.Background(), user)
		assert.Nil(err)
		uRole, err := NewAssignedRole(s, role, user)
		assert.Nil(err)
		assert.True(uRole != nil)
		assert.Equal(uRole.GetRoleId(), role.Id)
		assert.Equal(uRole.GetPrincipalId(), user.Id)
		err = w.Create(context.Background(), uRole)
		assert.Nil(err)
		assert.True(uRole != nil)
		assert.Equal(uRole.GetPrincipalId(), user.Id)
	})
	t.Run("nil-scope", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.Id != 0)

		role, err := NewRole(s)
		assert.Nil(err)
		assert.True(role != nil)
		assert.Equal(s.Id, role.PrimaryScopeId)
		err = w.Create(context.Background(), role)
		assert.Nil(err)
		assert.True(role.Id != 0)

		g, err := NewRoleGrant(nil, role, "everything*")
		assert.True(err != nil)
		assert.True(g == nil)
		assert.Equal(err.Error(), "error the role grant primary scope is nil")
	})
	t.Run("nil-role", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.Id != 0)

		g, err := NewRoleGrant(s, nil, "everything*")
		assert.True(err != nil)
		assert.True(g == nil)
		assert.Equal(err.Error(), "error role is nil")
	})
}

func TestRoleGrant_Actions(t *testing.T) {
	assert := assert.New(t)
	g := &RoleGrant{}
	a := g.Actions()
	assert.Equal(a[ActionList.String()], ActionList)
	assert.Equal(a[ActionCreate.String()], ActionCreate)
	assert.Equal(a[ActionUpdate.String()], ActionUpdate)
	assert.Equal(a[ActionRead.String()], ActionRead)
	assert.Equal(a[ActionDelete.String()], ActionDelete)
}

func TestRoleGrant_ResourceType(t *testing.T) {
	assert := assert.New(t)
	r := &RoleGrant{}
	ty := r.ResourceType()
	assert.Equal(ty, ResourceTypeRoleGrant)
}

func TestRoleGrant_GetPrimaryScope(t *testing.T) {
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

		role, err := NewRole(s)
		assert.Nil(err)
		assert.True(role != nil)
		assert.Equal(s.Id, role.PrimaryScopeId)
		err = w.Create(context.Background(), role)
		assert.Nil(err)
		assert.True(role.Id != 0)

		g, err := NewRoleGrant(s, role, "everything*")
		assert.Nil(err)
		assert.True(g != nil)
		assert.Equal(g.RoleId, role.Id)
		assert.Equal(g.Grant, "everything*")

		ps, err := g.GetPrimaryScope(context.Background(), &w)
		assert.Nil(err)
		assert.True(ps != nil)
		assert.Equal(ps.Id, s.Id)
	})
}

func TestRoleGrant_Clone(t *testing.T) {
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

		role, err := NewRole(s)
		assert.Nil(err)
		assert.True(role != nil)
		assert.Equal(s.Id, role.PrimaryScopeId)
		err = w.Create(context.Background(), role)
		assert.Nil(err)
		assert.True(role.Id != 0)

		g, err := NewRoleGrant(s, role, "everything*")
		assert.Nil(err)
		assert.True(g != nil)
		assert.Equal(g.RoleId, role.Id)
		assert.Equal(g.Grant, "everything*")

		cp := g.Clone()
		assert.True(proto.Equal(cp.(*RoleGrant).RoleGrant, g.RoleGrant))
	})
	t.Run("not-equal", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.Id != 0)

		role, err := NewRole(s)
		assert.Nil(err)
		assert.True(role != nil)
		assert.Equal(s.Id, role.PrimaryScopeId)
		err = w.Create(context.Background(), role)
		assert.Nil(err)
		assert.True(role.Id != 0)

		g, err := NewRoleGrant(s, role, "everything*")
		assert.Nil(err)
		assert.True(g != nil)
		assert.Equal(g.RoleId, role.Id)
		assert.Equal(g.Grant, "everything*")

		g2, err := NewRoleGrant(s, role, "nothing*")
		assert.Nil(err)
		assert.True(g2 != nil)
		assert.Equal(g2.RoleId, role.Id)
		assert.Equal(g2.Grant, "nothing*")

		cp := g.Clone()
		assert.True(!proto.Equal(cp.(*RoleGrant).RoleGrant, g2.RoleGrant))

	})
}
