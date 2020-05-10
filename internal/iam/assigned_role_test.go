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

		user, err := NewUser(s.PublicId)
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

		grp, err := NewGroup(s, WithDescription("this is a test group"))
		assert.Nil(err)
		assert.True(grp != nil)
		assert.Equal(grp.Description, "this is a test group")
		assert.Equal(s.PublicId, grp.ScopeId)
		err = w.Create(context.Background(), grp)
		assert.Nil(err)
		assert.True(grp.PublicId != "")

		gRole, err := NewAssignedRole(s, role, grp)
		assert.Nil(err)
		assert.True(gRole != nil)
		assert.Equal(gRole.GetRoleId(), role.PublicId)
		assert.Equal(gRole.GetPrincipalId(), grp.PublicId)
		err = w.Create(context.Background(), gRole)
		assert.Nil(err)
		assert.True(gRole != nil)
		assert.Equal(gRole.GetPrincipalId(), grp.PublicId)
	})
	t.Run("bad-resource-type", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewOrganization()
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		secondScope, err := NewOrganization()
		assert.Nil(err)
		assert.True(secondScope.Scope != nil)
		err = w.Create(context.Background(), secondScope)
		assert.Nil(err)
		assert.True(secondScope.PublicId != "")

		role, err := NewRole(s, WithDescription("this is a test role"))
		assert.Nil(err)
		assert.True(role != nil)
		assert.Equal(role.Description, "this is a test role")
		assert.Equal(s.PublicId, role.ScopeId)
		err = w.Create(context.Background(), role)
		assert.Nil(err)
		assert.True(role.PublicId != "")

		uRole, err := NewAssignedRole(s, role, secondScope)
		assert.True(err != nil)
		assert.True(uRole == nil)
		assert.Equal(err.Error(), "error unknown principal type for assigning role")
	})
	t.Run("nil-role", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewOrganization()
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		user, err := NewUser(s.PublicId)
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
		s, err := NewOrganization()
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		role, err := NewRole(s, WithDescription("this is a test role"))
		assert.Nil(err)
		assert.True(role != nil)
		assert.Equal(role.Description, "this is a test role")
		assert.Equal(s.PublicId, role.ScopeId)
		err = w.Create(context.Background(), role)
		assert.Nil(err)
		assert.True(role.PublicId != "")

		uRole, err := NewAssignedRole(s, role, nil)
		assert.True(err != nil)
		assert.True(uRole == nil)
		assert.Equal(err.Error(), "principal is nil for assigning role")
	})
	t.Run("nil-scope", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewOrganization()
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		role, err := NewRole(s, WithDescription("this is a test role"))
		assert.Nil(err)
		assert.True(role != nil)
		assert.Equal(role.Description, "this is a test role")
		assert.Equal(s.PublicId, role.ScopeId)
		err = w.Create(context.Background(), role)
		assert.Nil(err)
		assert.True(role.PublicId != "")

		user, err := NewUser(s.PublicId)
		assert.Nil(err)
		err = w.Create(context.Background(), user)
		assert.Nil(err)

		uRole, err := NewAssignedRole(nil, role, user)
		assert.True(err != nil)
		assert.True(uRole == nil)
		assert.Equal(err.Error(), "error scope is nil for assigning role")
	})
}
