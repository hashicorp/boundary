package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func Test_NewRole(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.NoError(err)
		assert.NotNil(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NoError(err)
		assert.NotEmpty(s.PublicId)

		role, err := NewRole(s.PublicId, WithDescription("this is a test role"))
		assert.NoError(err)
		assert.NotNil(role)
		assert.Equal(role.Description, "this is a test role")
		assert.Equal(s.PublicId, role.ScopeId)
		err = w.Create(context.Background(), role)
		assert.NoError(err)
		assert.NotEmpty(role.PublicId)
	})
	t.Run("no-scope", func(t *testing.T) {
		role, err := NewRole("")
		assert.Error(err)
		assert.Nil(role)
		assert.Equal(err.Error(), "error the role scope id is unset")
	})
}

func TestRole_Actions(t *testing.T) {
	assert := assert.New(t)
	r := &Role{}
	a := r.Actions()
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

func TestRole_GetScope(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.NoError(err)
		assert.NotNil(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NoError(err)
		assert.NotEmpty(s.PublicId)

		role, err := NewRole(s.PublicId, WithDescription("this is a test role"))
		assert.NoError(err)
		assert.NotNil(role)
		assert.Equal(role.Description, "this is a test role")
		assert.Equal(s.PublicId, role.ScopeId)
		err = w.Create(context.Background(), role)
		assert.NoError(err)
		assert.NotEmpty(role.PublicId)

		scope, err := role.GetScope(context.Background(), w)
		assert.NoError(err)
		assert.NotNil(scope)
	})
}

func TestRole_AssignedRoles(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.NoError(err)
		assert.NotNil(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NoError(err)
		assert.NotEmpty(s.PublicId)

		user := TestUser(t, conn, s.PublicId)

		role, err := NewRole(s.PublicId, WithDescription("this is a test role"))
		assert.NoError(err)
		assert.NotNil(role)
		assert.Equal(role.Description, "this is a test role")
		assert.Equal(s.PublicId, role.ScopeId)
		err = w.Create(context.Background(), role)
		assert.NoError(err)
		assert.NotEmpty(role.PublicId)

		uRole, err := NewAssignedRole(role, user)
		assert.NoError(err)
		assert.NotNil(uRole)
		assert.Equal(uRole.GetRoleId(), role.PublicId)
		assert.Equal(uRole.GetPrincipalId(), user.PublicId)
		err = w.Create(context.Background(), uRole)
		assert.NoError(err)
		assert.NotNil(uRole)
		assert.Equal(uRole.GetPrincipalId(), user.PublicId)

		grp, err := NewGroup(s.PublicId, WithDescription("this is a test group"))
		assert.NoError(err)
		assert.NotNil(grp)
		assert.Equal(grp.Description, "this is a test group")
		assert.Equal(s.PublicId, grp.ScopeId)
		err = w.Create(context.Background(), grp)
		assert.NoError(err)
		assert.NotEmpty(grp.PublicId)

		gRole, err := NewAssignedRole(role, grp)
		assert.NoError(err)
		assert.NotNil(gRole)
		assert.Equal(gRole.GetRoleId(), role.PublicId)
		assert.Equal(gRole.GetPrincipalId(), grp.PublicId)
		err = w.Create(context.Background(), gRole)
		assert.NoError(err)
		assert.NotNil(gRole)
		assert.Equal(gRole.GetPrincipalId(), grp.PublicId)

		allRoles, err := role.AssignedRoles(context.Background(), w)
		assert.NoError(err)
		assert.Equal(len(allRoles), 2)
	})
}

func TestRole_Clone(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.NoError(err)
		assert.NotNil(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NoError(err)
		assert.NotEmpty(s.PublicId)

		role, err := NewRole(s.PublicId, WithDescription("this is a test role"))
		assert.NoError(err)
		assert.NotNil(role)
		assert.Equal(role.Description, "this is a test role")
		assert.Equal(s.PublicId, role.ScopeId)
		err = w.Create(context.Background(), role)
		assert.NoError(err)
		assert.NotEmpty(role.PublicId)

		cp := role.Clone()
		assert.True(proto.Equal(cp.(*Role).Role, role.Role))
	})
	t.Run("not-equal", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.NoError(err)
		assert.NotNil(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NoError(err)
		assert.NotEmpty(s.PublicId)

		role, err := NewRole(s.PublicId, WithDescription("this is a test role"))
		assert.NoError(err)
		assert.NotNil(role)
		assert.Equal(role.Description, "this is a test role")
		assert.Equal(s.PublicId, role.ScopeId)
		err = w.Create(context.Background(), role)
		assert.NoError(err)
		assert.NotEmpty(role.PublicId)

		role2, err := NewRole(s.PublicId, WithDescription("this is a test role"))
		assert.NoError(err)
		assert.NotNil(role2)
		assert.Equal(role2.Description, "this is a test role")
		assert.Equal(s.PublicId, role2.ScopeId)
		err = w.Create(context.Background(), role2)
		assert.NoError(err)
		assert.NotEmpty(role2.PublicId)

		cp := role.Clone()
		assert.True(!proto.Equal(cp.(*Role).Role, role2.Role))
	})
}
