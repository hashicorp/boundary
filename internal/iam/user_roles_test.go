package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
)

func Test_UserRoles(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	org, _ := TestScopes(t, conn)
	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		w := db.New(conn)
		user := TestUser(t, conn, org.PublicId)
		role := TestRole(t, conn, org.PublicId, WithDescription("this is a test role"))

		uRole, err := NewUserRole(org.PublicId, role.PublicId, user.PublicId)
		assert.NoError(err)
		assert.NotNil(uRole)
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
