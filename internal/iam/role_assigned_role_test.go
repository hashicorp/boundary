package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRole_AssignedRoles(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := db.New(conn)
		s := testOrg(t, conn, "", "")
		user := TestUser(t, conn, s.PublicId)

		role, err := NewRole(s.PublicId, WithDescription("this is a test role"))
		assert.NoError(err)
		assert.NotNil(role)
		assert.Equal(role.Description, "this is a test role")
		assert.Equal(s.PublicId, role.ScopeId)
		role.PublicId, err = newRoleId()
		require.NoError(err)
		err = w.Create(context.Background(), role)
		assert.NoError(err)
		assert.NotEmpty(role.PublicId)

		uRole, err := NewUserRole(s.PublicId, role.PublicId, user.PublicId)
		assert.NoError(err)
		assert.NotNil(uRole)
		assert.Equal(uRole.GetRoleId(), role.PublicId)
		assert.Equal(uRole.GetPrincipalId(), user.PublicId)
		err = w.Create(context.Background(), uRole)
		assert.NoError(err)
		assert.NotNil(uRole)
		assert.Equal(uRole.GetPrincipalId(), user.PublicId)

		grp := TestGroup(t, conn, s.PublicId)

		gRole, err := NewGroupRole(s.PublicId, role.PublicId, grp.PublicId)
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
