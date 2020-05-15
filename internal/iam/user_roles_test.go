package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
)

func Test_UserRoles(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()
	org, _ := TestScopes(t, conn)

	t.Run("valid", func(t *testing.T) {
		w := db.New(conn)
		user, err := NewUser(org.PublicId)
		assert.NoError(err)
		err = w.Create(context.Background(), user)
		assert.NoError(err)

		role, err := NewRole(org.PublicId, WithDescription("this is a test role"))
		assert.NoError(err)
		assert.NotEqual(role, nil)
		assert.Equal(role.Description, "this is a test role")
		assert.Equal(org.PublicId, role.ScopeId)
		err = w.Create(context.Background(), role)
		assert.NoError(err)
		assert.NotEqual(role.PublicId, "")

		uRole, err := NewAssignedRole(role, user)
		assert.NoError(err)
		assert.True(uRole != nil)
		assert.Equal(uRole.GetRoleId(), role.PublicId)
		assert.Equal(uRole.GetPrincipalId(), user.PublicId)
		err = w.Create(context.Background(), uRole)
		assert.NoError(err)
		assert.NotNil(uRole)
		assert.Equal(uRole.GetPrincipalId(), user.PublicId)

		userRoles, err := user.Roles(context.Background(), w)
		assert.NoError(err)
		assert.Equal(len(userRoles), 1)
		assert.Equal(userRoles[role.PublicId], role)
	})
}
