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
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.NoError(err)
		assert.NotNil(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NoError(err)
		assert.True(s.PublicId != "")

		user, err := NewUser(s.PublicId)
		assert.NoError(err)
		err = w.Create(context.Background(), user)
		assert.NoError(err)

		role, err := NewRole(s.PublicId, WithDescription("this is a test role"))
		assert.NoError(err)
		assert.True(role != nil)
		assert.Equal(role.Description, "this is a test role")
		assert.Equal(s.PublicId, role.ScopeId)
		err = w.Create(context.Background(), role)
		assert.NoError(err)
		assert.True(role.PublicId != "")

		uRole, err := NewAssignedRole(role, user)
		assert.NoError(err)
		assert.True(uRole != nil)
		assert.Equal(uRole.GetRoleId(), role.PublicId)
		assert.Equal(uRole.GetPrincipalId(), user.PublicId)
		err = w.Create(context.Background(), uRole)
		assert.NoError(err)
		assert.True(uRole != nil)
		assert.Equal(uRole.GetPrincipalId(), user.PublicId)

		grp, err := NewGroup(s.PublicId, WithDescription("this is a test group"))
		assert.NoError(err)
		assert.True(grp != nil)
		assert.Equal(grp.Description, "this is a test group")
		assert.Equal(s.PublicId, grp.ScopeId)
		err = w.Create(context.Background(), grp)
		assert.NoError(err)
		assert.True(grp.PublicId != "")

		gRole, err := NewAssignedRole(role, grp)
		assert.NoError(err)
		assert.True(gRole != nil)
		assert.Equal(gRole.GetRoleId(), role.PublicId)
		assert.Equal(gRole.GetPrincipalId(), grp.PublicId)
		err = w.Create(context.Background(), gRole)
		assert.NoError(err)
		assert.True(gRole != nil)
		assert.Equal(gRole.GetPrincipalId(), grp.PublicId)
	})
	t.Run("bad-resource-type", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.NoError(err)
		assert.NotNil(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NoError(err)
		assert.True(s.PublicId != "")

		secondScope, err := NewOrganization()
		assert.NoError(err)
		assert.True(secondScope.Scope != nil)
		err = w.Create(context.Background(), secondScope)
		assert.NoError(err)
		assert.True(secondScope.PublicId != "")

		role, err := NewRole(s.PublicId, WithDescription("this is a test role"))
		assert.NoError(err)
		assert.True(role != nil)
		assert.Equal(role.Description, "this is a test role")
		assert.Equal(s.PublicId, role.ScopeId)
		err = w.Create(context.Background(), role)
		assert.NoError(err)
		assert.True(role.PublicId != "")

		uRole, err := NewAssignedRole(role, secondScope)
		assert.True(err != nil)
		assert.True(uRole == nil)
		assert.Equal(err.Error(), "error unknown principal type for assigning role")
	})
	t.Run("nil-role", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.NoError(err)
		assert.NotNil(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NoError(err)
		assert.True(s.PublicId != "")

		user, err := NewUser(s.PublicId)
		assert.NoError(err)
		err = w.Create(context.Background(), user)
		assert.NoError(err)

		uRole, err := NewAssignedRole(nil, user)
		assert.True(err != nil)
		assert.True(uRole == nil)
		assert.Equal(err.Error(), "error role is nil for assigning role")
	})
	t.Run("nil-principal", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.NoError(err)
		assert.NotNil(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NoError(err)
		assert.True(s.PublicId != "")

		role, err := NewRole(s.PublicId, WithDescription("this is a test role"))
		assert.NoError(err)
		assert.True(role != nil)
		assert.Equal(role.Description, "this is a test role")
		assert.Equal(s.PublicId, role.ScopeId)
		err = w.Create(context.Background(), role)
		assert.NoError(err)
		assert.True(role.PublicId != "")

		uRole, err := NewAssignedRole(role, nil)
		assert.True(err != nil)
		assert.True(uRole == nil)
		assert.Equal(err.Error(), "principal is nil for assigning role")
	})
	t.Run("nil-scope", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.NoError(err)
		assert.NotNil(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NoError(err)
		assert.True(s.PublicId != "")

		role, err := NewRole(s.PublicId, WithDescription("this is a test role"))
		assert.NoError(err)
		assert.True(role != nil)
		assert.Equal(role.Description, "this is a test role")
		assert.Equal(s.PublicId, role.ScopeId)
		err = w.Create(context.Background(), role)
		assert.NoError(err)
		assert.True(role.PublicId != "")

		user, err := NewUser(s.PublicId)
		assert.NoError(err)
		err = w.Create(context.Background(), user)
		assert.NoError(err)
	})
}
