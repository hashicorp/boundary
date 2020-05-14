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
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		user, err := NewUser(s.PublicId)
		assert.Nil(err)
		err = w.Create(context.Background(), user)
		assert.Nil(err)

		grp, err := NewGroup(s.PublicId, WithDescription("this is a test group"))
		assert.Nil(err)
		assert.True(grp != nil)
		assert.Equal(grp.Description, "this is a test group")
		assert.Equal(s.PublicId, grp.ScopeId)
		err = w.Create(context.Background(), grp)
		assert.Nil(err)
		assert.True(grp.PublicId != "")

		gm, err := NewGroupMember(grp, user)
		assert.Nil(err)
		assert.True(gm != nil)
		err = w.Create(context.Background(), gm)
		assert.Nil(err)

		members, err := grp.Members(context.Background(), w)
		assert.Nil(err)
		assert.Equal(1, len(members))
		assert.Equal(members[0].GetMemberId(), user.PublicId)
		assert.Equal(members[0].GetGroupId(), grp.PublicId)

		rowsDeleted, err := w.Delete(context.Background(), gm)
		assert.Nil(err)
		assert.Equal(1, rowsDeleted)

		members, err = grp.Members(context.Background(), w)
		assert.Nil(err)
		assert.Equal(0, len(members))
	})
	t.Run("bad-type", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		role, err := NewRole(s.PublicId)
		assert.Nil(err)
		assert.True(role != nil)
		assert.Equal(s.PublicId, role.ScopeId)
		err = w.Create(context.Background(), role)
		assert.Nil(err)
		assert.True(role.PublicId != "")

		grp, err := NewGroup(s.PublicId)
		assert.Nil(err)
		assert.True(grp != nil)
		assert.Equal(s.PublicId, grp.ScopeId)
		err = w.Create(context.Background(), grp)
		assert.Nil(err)
		assert.True(grp.PublicId != "")

		gm, err := NewGroupMember(grp, role)
		assert.True(err != nil)
		assert.True(gm == nil)
		assert.Equal(err.Error(), "error unknown group member type")
	})
	t.Run("nil-group", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		user, err := NewUser(s.PublicId)
		assert.Nil(err)
		err = w.Create(context.Background(), user)
		assert.Nil(err)

		gm, err := NewGroupMember(nil, user)
		assert.True(err != nil)
		assert.True(gm == nil)
		assert.Equal(err.Error(), "error group is nil for group member")
	})
	t.Run("nil-user", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		grp, err := NewGroup(s.PublicId)
		assert.Nil(err)
		assert.True(grp != nil)
		assert.Equal(s.PublicId, grp.ScopeId)
		err = w.Create(context.Background(), grp)
		assert.Nil(err)
		assert.True(grp.PublicId != "")

		gm, err := NewGroupMember(grp, nil)
		assert.True(err != nil)
		assert.True(gm == nil)
		assert.Equal(err.Error(), "member is nil for group member")
	})
}
