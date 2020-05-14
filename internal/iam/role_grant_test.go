package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func TestNewRoleGrant(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		role, err := NewRole(s.PublicId)
		assert.Nil(err)
		assert.True(role != nil)
		assert.Equal(s.PublicId, role.ScopeId)
		err = w.Create(context.Background(), role)
		assert.Nil(err)
		assert.True(role.PublicId != "")

		g, err := NewRoleGrant(s, role, "everything*")
		assert.Nil(err)
		assert.True(g != nil)
		assert.Equal(g.RoleId, role.PublicId)
		assert.Equal(g.Grant, "everything*")
		err = w.Create(context.Background(), g)
		assert.Nil(err)
		assert.True(g.PublicId != "")

		user, err := NewUser(s.PublicId)
		assert.Nil(err)
		err = w.Create(context.Background(), user)
		assert.Nil(err)
		uRole, err := NewAssignedRole(role, user)
		assert.Nil(err)
		assert.True(uRole != nil)
		assert.Equal(uRole.GetRoleId(), role.PublicId)
		assert.Equal(uRole.GetPrincipalId(), user.PublicId)
		err = w.Create(context.Background(), uRole)
		assert.Nil(err)
		assert.True(uRole != nil)
		assert.Equal(uRole.GetPrincipalId(), user.PublicId)
	})
	t.Run("nil-scope", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		role, err := NewRole(s.PublicId)
		assert.Nil(err)
		assert.True(role != nil)
		assert.Equal(s.PublicId, role.ScopeId)
		err = w.Create(context.Background(), role)
		assert.Nil(err)
		assert.True(role.PublicId != "")

		g, err := NewRoleGrant(nil, role, "everything*")
		assert.True(err != nil)
		assert.True(g == nil)
		assert.Equal(err.Error(), "error the role grant scope is nil")
	})
	t.Run("nil-role", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

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

func TestRoleGrant_GetScope(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		role, err := NewRole(s.PublicId)
		assert.Nil(err)
		assert.True(role != nil)
		assert.Equal(s.PublicId, role.ScopeId)
		err = w.Create(context.Background(), role)
		assert.Nil(err)
		assert.True(role.PublicId != "")

		g, err := NewRoleGrant(s, role, "everything*")
		assert.Nil(err)
		assert.True(g != nil)
		assert.Equal(g.RoleId, role.PublicId)
		assert.Equal(g.Grant, "everything*")

		ps, err := g.GetScope(context.Background(), w)
		assert.Nil(err)
		assert.True(ps != nil)
		assert.Equal(ps.PublicId, s.PublicId)
	})
}

func TestRoleGrant_Clone(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		role, err := NewRole(s.PublicId)
		assert.Nil(err)
		assert.True(role != nil)
		assert.Equal(s.PublicId, role.ScopeId)
		err = w.Create(context.Background(), role)
		assert.Nil(err)
		assert.True(role.PublicId != "")

		g, err := NewRoleGrant(s, role, "everything*")
		assert.Nil(err)
		assert.True(g != nil)
		assert.Equal(g.RoleId, role.PublicId)
		assert.Equal(g.Grant, "everything*")

		cp := g.Clone()
		assert.True(proto.Equal(cp.(*RoleGrant).RoleGrant, g.RoleGrant))
	})
	t.Run("not-equal", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		role, err := NewRole(s.PublicId)
		assert.Nil(err)
		assert.True(role != nil)
		assert.Equal(s.PublicId, role.ScopeId)
		err = w.Create(context.Background(), role)
		assert.Nil(err)
		assert.True(role.PublicId != "")

		g, err := NewRoleGrant(s, role, "everything*")
		assert.Nil(err)
		assert.True(g != nil)
		assert.Equal(g.RoleId, role.PublicId)
		assert.Equal(g.Grant, "everything*")

		g2, err := NewRoleGrant(s, role, "nothing*")
		assert.Nil(err)
		assert.True(g2 != nil)
		assert.Equal(g2.RoleId, role.PublicId)
		assert.Equal(g2.Grant, "nothing*")

		cp := g.Clone()
		assert.True(!proto.Equal(cp.(*RoleGrant).RoleGrant, g2.RoleGrant))

	})
}
