package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func Test_NewGroup(t *testing.T) {
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
		assert.True(s.Id != 0)

		grp, err := NewGroup(s, WithDescription("this is a test group"))
		assert.Nil(err)
		assert.True(grp != nil)
		assert.Equal(grp.Description, "this is a test group")
		assert.Equal(s.Id, grp.PrimaryScopeId)
		err = w.Create(context.Background(), grp)
		assert.Nil(err)
		assert.True(grp.Id != 0)
	})
	t.Run("nil-scope", func(t *testing.T) {
		grp, err := NewGroup(nil)
		assert.True(err != nil)
		assert.True(grp == nil)
		assert.Equal(err.Error(), "error the group primary scope is nil")
	})
}

func TestGroup_Members(t *testing.T) {
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
		assert.True(s.Id != 0)

		user, err := NewUser(s)
		assert.Nil(err)
		err = w.Create(context.Background(), user)
		assert.Nil(err)

		grp, err := NewGroup(s, WithDescription("this is a test group"))
		assert.Nil(err)
		assert.True(grp != nil)
		assert.Equal(grp.Description, "this is a test group")
		assert.Equal(s.Id, grp.PrimaryScopeId)
		err = w.Create(context.Background(), grp)
		assert.Nil(err)
		assert.True(grp.Id != 0)

		gm, err := NewGroupMember(s, grp, user)
		assert.Nil(err)
		assert.True(gm != nil)
		err = w.Create(context.Background(), gm)
		assert.Nil(err)

		secondUser, err := NewUser(s)
		assert.Nil(err)
		assert.True(secondUser != nil)
		err = w.Create(context.Background(), secondUser)
		assert.Nil(err)

		gm2, err := NewGroupMember(s, grp, secondUser)
		assert.Nil(err)
		assert.True(gm2 != nil)
		err = w.Create(context.Background(), gm2)
		assert.Nil(err)

		members, err := grp.Members(context.Background(), &w)
		assert.Nil(err)
		assert.True(members != nil)
		assert.True(len(members) == 2)
		for _, m := range members {
			if m.GetMemberId() != secondUser.Id && m.GetMemberId() != user.Id {
				t.Errorf("members %d not one of the known ids %d, %d", m.GetMemberId(), secondUser.Id, user.Id)
			}
		}
	})
}

func TestGroup_Actions(t *testing.T) {
	assert := assert.New(t)
	r := &Group{}
	a := r.Actions()
	assert.Equal(a[ActionList.String()], ActionList)
	assert.Equal(a[ActionCreate.String()], ActionCreate)
	assert.Equal(a[ActionUpdate.String()], ActionUpdate)
	assert.Equal(a[ActionRead.String()], ActionRead)
	assert.Equal(a[ActionDelete.String()], ActionDelete)
}

func TestGroup_ResourceType(t *testing.T) {
	assert := assert.New(t)
	r := &Group{}
	ty := r.ResourceType()
	assert.Equal(ty, ResourceTypeGroup)
}

func TestGroup_GetPrimaryScope(t *testing.T) {
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
		assert.True(s.Id != 0)

		grp, err := NewGroup(s)
		assert.Nil(err)
		assert.True(grp != nil)
		assert.Equal(s.Id, grp.PrimaryScopeId)
		err = w.Create(context.Background(), grp)
		assert.Nil(err)
		assert.True(grp.Id != 0)

		primaryScope, err := grp.GetPrimaryScope(context.Background(), &w)
		assert.Nil(err)
		assert.True(primaryScope != nil)
	})
}

func TestGroup_AddMember(t *testing.T) {
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
		assert.True(s.Id != 0)

		user, err := NewUser(s)
		assert.Nil(err)
		err = w.Create(context.Background(), user)
		assert.Nil(err)

		grp, err := NewGroup(s, WithDescription("this is a test group"))
		assert.Nil(err)
		assert.True(grp != nil)
		assert.Equal(grp.Description, "this is a test group")
		assert.Equal(s.Id, grp.PrimaryScopeId)
		err = w.Create(context.Background(), grp)
		assert.Nil(err)
		assert.True(grp.Id != 0)

		gm, err := grp.AddMember(context.Background(), &w, user)
		assert.Nil(err)
		assert.True(gm != nil)
		assert.Equal(gm.(*GroupMemberUser).PrimaryScopeId, grp.PrimaryScopeId)
		err = w.Create(context.Background(), gm)
		assert.Nil(err)
		assert.True(gm.GetPublicId() != "")
	})
}

func TestGroup_Clone(t *testing.T) {
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
		assert.True(s.Id != 0)

		grp, err := NewGroup(s, WithDescription("this is a test group"))
		assert.Nil(err)
		assert.True(grp != nil)
		assert.Equal(grp.Description, "this is a test group")
		assert.Equal(s.Id, grp.PrimaryScopeId)
		err = w.Create(context.Background(), grp)
		assert.Nil(err)
		assert.True(grp.Id != 0)

		cp := grp.Clone()
		assert.True(proto.Equal(cp.(*Group).Group, grp.Group))
	})
	t.Run("not-equal", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.Id != 0)

		grp, err := NewGroup(s, WithDescription("this is a test group"))
		assert.Nil(err)
		assert.True(grp != nil)
		assert.Equal(grp.Description, "this is a test group")
		assert.Equal(s.Id, grp.PrimaryScopeId)
		err = w.Create(context.Background(), grp)
		assert.Nil(err)
		assert.True(grp.Id != 0)

		grp2, err := NewGroup(s, WithDescription("second group"))
		assert.Nil(err)
		assert.True(grp2 != nil)
		err = w.Create(context.Background(), grp2)
		assert.Nil(err)
		assert.True(grp2.Id != 0)

		cp := grp.Clone()
		assert.True(!proto.Equal(cp.(*Group).Group, grp2.Group))
	})
}
