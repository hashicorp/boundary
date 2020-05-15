package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
)

func Test_UserGrants(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		id, err := uuid.GenerateUUID()
		assert.NoError(err)
		w := db.New(conn)
		org, err := NewOrganization()
		assert.NoError(err)
		assert.NotNil(org.Scope)
		err = w.Create(context.Background(), org)
		assert.NoError(err)
		assert.NotEqual(org.PublicId, "")

		role, err := NewRole(org.PublicId)
		assert.NoError(err)
		assert.NotNil(role)
		assert.Equal(org.PublicId, role.ScopeId)
		err = w.Create(context.Background(), role)
		assert.NoError(err)
		assert.NotEqual(role.PublicId, "")

		g, err := NewRoleGrant(role, "everything*"+id)
		assert.NoError(err)
		assert.NotNil(g)
		assert.Equal(g.RoleId, role.PublicId)
		assert.Equal(g.Grant, "everything*"+id)
		err = w.Create(context.Background(), g)
		assert.NoError(err)
		assert.NotEqual(g.PublicId, "")

		user, err := NewUser(org.PublicId)
		assert.NoError(err)
		err = w.Create(context.Background(), user)
		assert.NoError(err)
		uRole, err := NewAssignedRole(role, user)
		assert.NoError(err)
		assert.NotNil(uRole)
		assert.Equal(uRole.GetRoleId(), role.PublicId)
		assert.Equal(uRole.GetPrincipalId(), user.PublicId)
		err = w.Create(context.Background(), uRole)
		assert.NoError(err)
		assert.NotNil(uRole)
		assert.Equal(uRole.GetPrincipalId(), user.PublicId)

		userGrants, err := user.Grants(context.Background(), w)
		assert.NoError(err)
		assert.Equal(len(userGrants), 1)
		assert.Equal(userGrants[0], g)

		grp, err := NewGroup(org.PublicId, WithDescription("user grants test group"))
		assert.NoError(err)
		assert.True(grp != nil)
		assert.Equal(grp.Description, "user grants test group")
		assert.Equal(org.PublicId, grp.ScopeId)
		err = w.Create(context.Background(), grp)
		assert.NoError(err)
		assert.NotEqual(grp.PublicId, "")

		gm, err := NewGroupMember(grp, user)
		assert.NoError(err)
		assert.NotNil(gm)
		err = w.Create(context.Background(), gm)
		assert.NoError(err)

		groupRole, err := NewRole(org.PublicId)
		assert.NoError(err)
		assert.NotNil(role)
		assert.Equal(org.PublicId, groupRole.ScopeId)
		err = w.Create(context.Background(), groupRole)
		assert.NoError(err)
		assert.NotEqual(groupRole.PublicId, "")

		groupGrant, err := NewRoleGrant(groupRole, "group-grant*"+id)
		assert.NoError(err)
		assert.True(groupGrant != nil)
		assert.Equal(groupGrant.RoleId, groupRole.PublicId)
		assert.Equal(groupGrant.Grant, "group-grant*"+id)
		err = w.Create(context.Background(), groupGrant)
		assert.NoError(err)
		assert.NotEqual(groupGrant.PublicId, "")

		gRole, err := NewAssignedRole(groupRole, grp)
		assert.NoError(err)
		assert.NotNil(gRole)
		assert.Equal(gRole.GetRoleId(), groupRole.PublicId)
		assert.Equal(gRole.GetPrincipalId(), grp.PublicId)
		err = w.Create(context.Background(), gRole)
		assert.NoError(err)
		assert.NotNil(gRole)
		assert.Equal(gRole.GetPrincipalId(), grp.PublicId)

		allGrants, err := user.Grants(context.Background(), w, WithGroupGrants(true))
		assert.NoError(err)
		assert.Equal(len(allGrants), 2)
		for _, grant := range allGrants {
			assert.True(grant.PublicId == g.PublicId || grant.PublicId == groupGrant.PublicId)
		}
	})
}
