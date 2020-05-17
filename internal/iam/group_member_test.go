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
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.NoError(err)
		assert.NotNil(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NoError(err)
		assert.NotEmpty(s.PublicId)

		user, err := NewUser(s.PublicId)
		assert.NoError(err)
		err = w.Create(context.Background(), user)
		assert.NoError(err)

		grp, err := NewGroup(s.PublicId, WithDescription("this is a test group"))
		assert.NoError(err)
		assert.NotNil(grp)
		assert.Equal(grp.Description, "this is a test group")
		assert.Equal(s.PublicId, grp.ScopeId)
		err = w.Create(context.Background(), grp)
		assert.NoError(err)
		assert.NotEmpty(grp.PublicId)

		gm, err := NewGroupMember(grp, user)
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
		w := db.New(conn)
		s, err := NewOrganization()
		assert.NoError(err)
		assert.NotNil(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NoError(err)
		assert.NotEmpty(s.PublicId)

		role, err := NewRole(s.PublicId)
		assert.NoError(err)
		assert.NotNil(role)
		assert.Equal(s.PublicId, role.ScopeId)
		err = w.Create(context.Background(), role)
		assert.NoError(err)
		assert.NotEmpty(role.PublicId)

		grp, err := NewGroup(s.PublicId)
		assert.NoError(err)
		assert.NotNil(grp)
		assert.Equal(s.PublicId, grp.ScopeId)
		err = w.Create(context.Background(), grp)
		assert.NoError(err)
		assert.NotEmpty(grp.PublicId)

		gm, err := NewGroupMember(grp, role)
		assert.Error(err)
		assert.Nil(gm)
		assert.Equal(err.Error(), "error unknown group member type")
	})
	t.Run("nil-group", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.NoError(err)
		assert.NotNil(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NoError(err)
		assert.NotEmpty(s.PublicId)

		user, err := NewUser(s.PublicId)
		assert.NoError(err)
		err = w.Create(context.Background(), user)
		assert.NoError(err)

		gm, err := NewGroupMember(nil, user)
		assert.Error(err)
		assert.Nil(gm)
		assert.Equal(err.Error(), "error group is nil for group member")
	})
	t.Run("nil-user", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.NoError(err)
		assert.NotNil(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NoError(err)
		assert.NotEmpty(s.PublicId)

		grp, err := NewGroup(s.PublicId)
		assert.NoError(err)
		assert.NotNil(grp)
		assert.Equal(s.PublicId, grp.ScopeId)
		err = w.Create(context.Background(), grp)
		assert.NoError(err)
		assert.NotEmpty(grp.PublicId)

		gm, err := NewGroupMember(grp, nil)
		assert.Error(err)
		assert.Nil(gm)
		assert.Equal(err.Error(), "member is nil for group member")
	})
}
