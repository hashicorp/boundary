package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"gotest.tools/assert"
)

func Test_NewGroup(t *testing.T) {
	db.StartTest()
	t.Parallel()
	cleanup, url := db.SetupTest(t, "../db/migrations/postgres")
	defer cleanup()
	defer db.CompleteTest() // must come after the "defer cleanup()"
	conn, err := db.TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.NilError(t, err)
		assert.Check(t, s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NilError(t, err)
		assert.Check(t, s.Id != 0)

		grp, err := NewGroup(s, WithDescription("this is a test group"))
		assert.NilError(t, err)
		assert.Check(t, grp != nil)
		assert.Equal(t, grp.Description, "this is a test group")
		assert.Equal(t, s.Id, grp.PrimaryScopeId)
		err = w.Create(context.Background(), grp)
		assert.NilError(t, err)
		assert.Check(t, grp.Id != 0)
	})
}

func Test_GroupMembers(t *testing.T) {
	db.StartTest()
	t.Parallel()
	cleanup, url := db.SetupTest(t, "../db/migrations/postgres")
	defer cleanup()
	defer db.CompleteTest() // must come after the "defer cleanup()"
	conn, err := db.TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.NilError(t, err)
		assert.Check(t, s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NilError(t, err)
		assert.Check(t, s.Id != 0)

		user, err := NewUser(s)
		assert.NilError(t, err)
		err = w.Create(context.Background(), user)
		assert.NilError(t, err)

		grp, err := NewGroup(s, WithDescription("this is a test group"))
		assert.NilError(t, err)
		assert.Check(t, grp != nil)
		assert.Equal(t, grp.Description, "this is a test group")
		assert.Equal(t, s.Id, grp.PrimaryScopeId)
		err = w.Create(context.Background(), grp)
		assert.NilError(t, err)
		assert.Check(t, grp.Id != 0)

		gm, err := NewGroupMember(s, grp, user)
		assert.NilError(t, err)
		assert.Check(t, gm != nil)
		err = w.Create(context.Background(), gm)
		assert.NilError(t, err)

		secondUser, err := NewUser(s)
		assert.NilError(t, err)
		assert.Check(t, secondUser != nil)
		err = w.Create(context.Background(), secondUser)
		assert.NilError(t, err)

		gm2, err := NewGroupMember(s, grp, secondUser)
		assert.NilError(t, err)
		assert.Check(t, gm2 != nil)
		err = w.Create(context.Background(), gm2)
		assert.NilError(t, err)

		members, err := grp.Members(context.Background(), &w)
		assert.NilError(t, err)
		assert.Check(t, members != nil)
		assert.Check(t, len(members) == 2)
		for _, m := range members {
			if m.GetMemberId() != secondUser.Id && m.GetMemberId() != user.Id {
				t.Errorf("members %d not one of the known ids %d, %d", m.GetMemberId(), secondUser.Id, user.Id)
			}
		}
	})
}
