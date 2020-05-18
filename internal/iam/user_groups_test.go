package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
)

func Test_UserGroups(t *testing.T) {
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

		grp, err := NewGroup(org.PublicId, WithDescription("this is a test group"))
		assert.NoError(err)
		assert.NotNil(grp)
		assert.Equal(grp.Description, "this is a test group")
		assert.Equal(org.PublicId, grp.ScopeId)
		err = w.Create(context.Background(), grp)
		assert.NoError(err)
		assert.NotEqual(grp.PublicId, "")

		gm, err := grp.AddUser(user.PublicId)
		assert.NoError(err)
		assert.NotNil(gm)
		err = w.Create(context.Background(), gm)
		assert.NoError(err)

		group, err := user.Groups(context.Background(), w)
		assert.NoError(err)
		assert.Equal(len(group), 1)
		assert.Equal(group[0], grp)
	})
}
