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

		uRole, err := NewUserRole(role.PublicId, user.PublicId)
		assert.NoError(err)
		assert.NotNil(uRole)
		assert.Equal(uRole.GetRoleId(), role.PublicId)
		assert.Equal(uRole.GetPrincipalId(), user.PublicId)
		err = w.Create(context.Background(), uRole)
		assert.NoError(err)
		assert.NotNil(uRole)
		assert.Equal(uRole.GetPrincipalId(), user.PublicId)

		grp := TestGroup(t, conn, s.PublicId)

		gRole, err := NewGroupRole(role.PublicId, grp.PublicId)
		assert.NoError(err)
		assert.NotNil(gRole)
		assert.Equal(gRole.GetRoleId(), role.PublicId)
		assert.Equal(gRole.GetPrincipalId(), grp.PublicId)
		err = w.Create(context.Background(), gRole)
		assert.NoError(err)
		assert.NotNil(gRole)
		assert.Equal(gRole.GetPrincipalId(), grp.PublicId)
	})
	t.Run("empty-role-id", func(t *testing.T) {
		assert := assert.New(t)
		s := testOrg(t, conn, "", "")
		user := TestUser(t, conn, s.PublicId)

		uRole, err := NewUserRole("", user.PublicId)
		assert.Error(err)
		assert.Nil(uRole)
	})
	t.Run("empty-user-id", func(t *testing.T) {
		assert := assert.New(t)
		s := testOrg(t, conn, "", "")
		role := TestRole(t, conn, s.PublicId, WithDescription("this is a test role"))
		uRole, err := NewUserRole(role.PublicId, "")
		assert.Error(err)
		assert.Nil(uRole)
	})
}
