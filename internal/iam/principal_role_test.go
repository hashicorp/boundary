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
		err := cleanup()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
	}()
	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		w := db.New(conn)
		s := testOrg(t, conn, "", "")
		user := TestUser(t, conn, s.PublicId)
		role := TestRole(t, conn, s.PublicId, WithDescription("this is a test role"))

		uRole, err := NewAssignedRole(role, user)
		assert.NoError(err)
		assert.NotNil(uRole)
		assert.Equal(uRole.GetRoleId(), role.PublicId)
		assert.Equal(uRole.GetPrincipalId(), user.PublicId)
		err = w.Create(context.Background(), uRole)
		assert.NoError(err)
		assert.NotNil(uRole)
		assert.Equal(uRole.GetPrincipalId(), user.PublicId)

		grp := TestGroup(t, conn, s.PublicId)

		gRole, err := NewAssignedRole(role, grp)
		assert.NoError(err)
		assert.NotNil(gRole)
		assert.Equal(gRole.GetRoleId(), role.PublicId)
		assert.Equal(gRole.GetPrincipalId(), grp.PublicId)
		err = w.Create(context.Background(), gRole)
		assert.NoError(err)
		assert.NotNil(gRole)
		assert.Equal(gRole.GetPrincipalId(), grp.PublicId)
	})
	t.Run("bad-resource-type", func(t *testing.T) {
		assert := assert.New(t)
		s := testOrg(t, conn, "", "")
		secondScope := testOrg(t, conn, "", "")
		role := TestRole(t, conn, s.PublicId, WithDescription("this is a test role"))

		uRole, err := NewAssignedRole(role, secondScope)
		assert.Error(err)
		assert.Nil(uRole)
		assert.Equal(err.Error(), "error unknown principal type for assigning role")
	})
	t.Run("nil-role", func(t *testing.T) {
		assert := assert.New(t)
		s := testOrg(t, conn, "", "")
		user := TestUser(t, conn, s.PublicId)

		uRole, err := NewAssignedRole(nil, user)
		assert.Error(err)
		assert.Nil(uRole)
		assert.Equal(err.Error(), "error role is nil for assigning role")
	})
	t.Run("nil-principal", func(t *testing.T) {
		assert := assert.New(t)
		s := testOrg(t, conn, "", "")
		role := TestRole(t, conn, s.PublicId, WithDescription("this is a test role"))

		uRole, err := NewAssignedRole(role, nil)
		assert.Error(err)
		assert.Nil(uRole)
		assert.Equal(err.Error(), "principal is nil for assigning role")
	})
}
