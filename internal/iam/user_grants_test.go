package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
)

func Test_RawGrants(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	org, _ := TestScopes(t, conn)

	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		w := db.New(conn)
		role := TestRole(t, conn, org.PublicId)

		g, err := NewRoleGrant(role.PublicId, "id=*;actions=*")
		assert.NoError(err)
		assert.NotNil(g)
		assert.Equal(g.RoleId, role.PublicId)
		assert.Equal(g.RawGrant, "id=*;actions=*")
		err = w.Create(context.Background(), g)
		assert.NoError(err)

		user := TestUser(t, conn, org.PublicId)
		uRole, err := NewUserRole(org.PublicId, role.PublicId, user.PublicId)
		assert.NoError(err)
		assert.NotNil(uRole)
		assert.Equal(uRole.GetRoleId(), role.PublicId)
		assert.Equal(uRole.GetPrincipalId(), user.PublicId)
		err = w.Create(context.Background(), uRole)
		assert.NoError(err)
		assert.NotNil(uRole)
		assert.Equal(uRole.GetPrincipalId(), user.PublicId)

		rawGrants, err := user.Grants(context.Background(), w)
		assert.NoError(err)
		assert.Equal(len(rawGrants), 1)
		assert.Equal(rawGrants[0], g)

		grp := TestGroup(t, conn, org.PublicId)

		gm, err := grp.AddUser(user.PublicId)
		assert.NoError(err)
		assert.NotNil(gm)
		err = w.Create(context.Background(), gm)
		assert.NoError(err)

		groupRole := TestRole(t, conn, org.PublicId)
		groupGrant, err := NewRoleGrant(groupRole.PublicId, "id=*;actions=*")
		assert.NoError(err)
		assert.NotNil(groupGrant)
		assert.Equal(groupGrant.RoleId, groupRole.PublicId)
		assert.Equal(groupGrant.RawGrant, "id=*;actions=*")
		err = w.Create(context.Background(), groupGrant)
		assert.NoError(err)

		gRole, err := NewGroupRole(org.PublicId, groupRole.PublicId, grp.PublicId)
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
			assert.True(grant.CanonicalGrant == g.CanonicalGrant || grant.CanonicalGrant == groupGrant.CanonicalGrant)
		}
	})
}
