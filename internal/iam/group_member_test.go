package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
)

func Test_NewGroupMember(t *testing.T) {
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
		grp := TestGroup(t, conn, s.PublicId)

		gm, err := NewGroupMember(grp.PublicId, user.PublicId)
		assert.NoError(err)
		assert.NotNil(gm)
		err = w.Create(context.Background(), gm)
		assert.NoError(err)

		// members, err := grp.Members(context.Background(), w)
		// assert.NoError(err)
		// assert.Equal(1, len(members))
		// assert.Equal(members[0].GetMemberId(), user.PublicId)
		// assert.Equal(members[0].GetGroupId(), grp.PublicId)

		// rowsDeleted, err := w.Delete(context.Background(), gm)
		// assert.NoError(err)
		// assert.Equal(1, rowsDeleted)

		// members, err = grp.Members(context.Background(), w)
		// assert.NoError(err)
		// assert.Equal(0, len(members))
	})
	t.Run("bad-type", func(t *testing.T) {
		assert := assert.New(t)
		w := db.New(conn)
		s := testOrg(t, conn, "", "")
		role := TestRole(t, conn, s.PublicId)

		grp := TestGroup(t, conn, s.PublicId)
		gm, err := NewGroupMember(grp.PublicId, role.PublicId)
		assert.NoError(err)
		assert.NotNil(gm)
		err = w.Create(context.Background(), gm)
		assert.Error(err)
		assert.Equal(err.Error(), `create: failed pq: insert or update on table "iam_group_member" violates foreign key constraint "iam_group_member_member_id_fkey"`)

	})
	t.Run("nil-user", func(t *testing.T) {
		assert := assert.New(t)
		s := testOrg(t, conn, "", "")
		grp := TestGroup(t, conn, s.PublicId)

		gm, err := NewGroupMember(grp.PublicId, "")
		assert.Error(err)
		assert.Nil(gm)
		assert.Equal(err.Error(), "new group member: missing user id: invalid parameter")
	})
}
