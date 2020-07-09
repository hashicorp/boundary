package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
)

func Test_UserGroups(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	org, _ := TestScopes(t, conn)
	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		w := db.New(conn)
		user := TestUser(t, conn, org.PublicId)

		grp := TestGroup(t, conn, org.PublicId)

		gm, err := NewGroupMember(grp.PublicId, user.PublicId)

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
