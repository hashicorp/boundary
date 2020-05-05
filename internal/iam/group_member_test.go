package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
)

func Test_NewGroupMember(t *testing.T) {
	db.StartTest()
	t.Parallel()
	cleanup, url := db.SetupTest(t, "../db/migrations/postgres")
	defer cleanup()
	defer db.CompleteTest() // must come after the "defer cleanup()"
	conn, err := db.TestConnection(url)
	assert := assert.New(t)
	assert.Nil(err)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		user, err := NewUser(s)
		assert.Nil(err)
		err = w.Create(context.Background(), user)
		assert.Nil(err)

		grp, err := NewGroup(s, WithDescription("this is a test group"))
		assert.Nil(err)
		assert.True(grp != nil)
		assert.Equal(grp.Description, "this is a test group")
		assert.Equal(s.PublicId, grp.PrimaryScopeId)
		err = w.Create(context.Background(), grp)
		assert.Nil(err)
		assert.True(grp.Id != 0)

		gm, err := NewGroupMember(s, grp, user)
		assert.Nil(err)
		assert.True(gm != nil)
		err = w.Create(context.Background(), gm)
		assert.Nil(err)

	})
	t.Run("bad-type", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		role, err := NewRole(s)
		assert.Nil(err)
		assert.True(role != nil)
		assert.Equal(s.PublicId, role.PrimaryScopeId)
		err = w.Create(context.Background(), role)
		assert.Nil(err)
		assert.True(role.Id != 0)

		grp, err := NewGroup(s)
		assert.Nil(err)
		assert.True(grp != nil)
		assert.Equal(s.PublicId, grp.PrimaryScopeId)
		err = w.Create(context.Background(), grp)
		assert.Nil(err)
		assert.True(grp.Id != 0)

		gm, err := NewGroupMember(s, grp, role)
		assert.True(err != nil)
		assert.True(gm == nil)
		assert.Equal(err.Error(), "error unknown group member type")
	})
	t.Run("nil-group", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		user, err := NewUser(s)
		assert.Nil(err)
		err = w.Create(context.Background(), user)
		assert.Nil(err)

		gm, err := NewGroupMember(s, nil, user)
		assert.True(err != nil)
		assert.True(gm == nil)
		assert.Equal(err.Error(), "error group is nil for group member")
	})
	t.Run("nil-user", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		grp, err := NewGroup(s)
		assert.Nil(err)
		assert.True(grp != nil)
		assert.Equal(s.PublicId, grp.PrimaryScopeId)
		err = w.Create(context.Background(), grp)
		assert.Nil(err)
		assert.True(grp.Id != 0)

		gm, err := NewGroupMember(s, grp, nil)
		assert.True(err != nil)
		assert.True(gm == nil)
		assert.Equal(err.Error(), "member is nil for group member")
	})

	t.Run("nil-scope", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		grp, err := NewGroup(s)
		assert.Nil(err)
		assert.True(grp != nil)
		assert.Equal(s.PublicId, grp.PrimaryScopeId)
		err = w.Create(context.Background(), grp)
		assert.Nil(err)
		assert.True(grp.Id != 0)

		user, err := NewUser(s)
		assert.Nil(err)
		err = w.Create(context.Background(), user)
		assert.Nil(err)

		gm, err := NewGroupMember(nil, grp, nil)
		assert.True(err != nil)
		assert.True(gm == nil)
		assert.Equal(err.Error(), "error scope is nil for group member")
	})
}

func TestGroupMemberUser_GetPrimaryScope(t *testing.T) {
	db.StartTest()
	t.Parallel()
	cleanup, url := db.SetupTest(t, "../db/migrations/postgres")
	defer cleanup()
	defer db.CompleteTest() // must come after the "defer cleanup()"
	conn, err := db.TestConnection(url)
	assert := assert.New(t)
	assert.Nil(err)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		user, err := NewUser(s)
		assert.Nil(err)
		err = w.Create(context.Background(), user)
		assert.Nil(err)

		grp, err := NewGroup(s, WithDescription("this is a test group"))
		assert.Nil(err)
		assert.True(grp != nil)
		assert.Equal(grp.Description, "this is a test group")
		assert.Equal(s.PublicId, grp.PrimaryScopeId)
		err = w.Create(context.Background(), grp)
		assert.Nil(err)
		assert.True(grp.Id != 0)

		gm, err := NewGroupMember(s, grp, user)
		assert.Nil(err)
		assert.True(gm != nil)
		err = w.Create(context.Background(), gm)
		assert.Nil(err)

		primaryScope, err := gm.GetPrimaryScope(context.Background(), &w)
		assert.Nil(err)
		assert.True(primaryScope != nil)
	})
}

func TestGroupMemberUser_Actions(t *testing.T) {
	assert := assert.New(t)
	r := &GroupMemberUser{}
	a := r.Actions()
	assert.Equal(a[ActionList.String()], ActionList)
	assert.Equal(a[ActionCreate.String()], ActionCreate)
	assert.Equal(a[ActionUpdate.String()], ActionUpdate)
	assert.Equal(a[ActionRead.String()], ActionRead)
	assert.Equal(a[ActionDelete.String()], ActionDelete)
}

func TestGroupMemberUser_ResourceType(t *testing.T) {
	assert := assert.New(t)
	r := &GroupMemberUser{}
	ty := r.ResourceType()
	assert.Equal(ty, ResourceTypeGroupUserMember)
}
