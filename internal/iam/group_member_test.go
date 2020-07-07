package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
)

func TestGroup_AddUser(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		w := db.New(conn)
		org, _ := TestScopes(t, conn)
		user := TestUser(t, conn, org.PublicId)
		grp := TestGroup(t, conn, org.PublicId)
		gm, err := grp.AddUser(user.PublicId)
		assert.NoError(err)
		assert.NotNil(gm)
		assert.Equal(gm.(*GroupMemberUser).GroupId, grp.PublicId)
		err = w.Create(context.Background(), gm)
		assert.NoError(err)
		assert.Equal("user", gm.GetType())
	})
}

func Test_NewGroupMember(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		w := db.New(conn)
		s := testOrg(t, conn, "", "")
		user := TestUser(t, conn, s.PublicId)
		grp := TestGroup(t, conn, s.PublicId)

		gm, err := grp.AddUser(user.PublicId)
		assert.NoError(err)
		assert.NotNil(gm)
		err = w.Create(context.Background(), gm)
		assert.NoError(err)

		members, err := grp.Members(context.Background(), w)
		assert.NoError(err)
		assert.Equal(1, len(members))
		assert.Equal(members[0].GetMemberId(), user.PublicId)
		assert.Equal(members[0].GetGroupId(), grp.PublicId)

		rowsDeleted, err := w.Delete(context.Background(), gm)
		assert.NoError(err)
		assert.Equal(1, rowsDeleted)

		members, err = grp.Members(context.Background(), w)
		assert.NoError(err)
		assert.Equal(0, len(members))
	})
	t.Run("bad-type", func(t *testing.T) {
		assert := assert.New(t)
		w := db.New(conn)
		s := testOrg(t, conn, "", "")
		role := TestRole(t, conn, s.PublicId)

		grp := TestGroup(t, conn, s.PublicId)
		gm, err := grp.AddUser(role.PublicId)
		assert.NoError(err)
		assert.NotNil(gm)
		err = w.Create(context.Background(), gm)
		assert.Error(err)
		assert.Equal(err.Error(), `create: failed: pq: insert or update on table "iam_group_member_user" violates foreign key constraint "iam_group_member_user_member_id_fkey"`)

	})
	t.Run("nil-user", func(t *testing.T) {
		assert := assert.New(t)
		s := testOrg(t, conn, "", "")
		grp := TestGroup(t, conn, s.PublicId)

		gm, err := grp.AddUser("")
		assert.Error(err)
		assert.Nil(gm)
		assert.Equal(err.Error(), "error the user public id is unset")
	})
}
