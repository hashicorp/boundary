package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func Test_NewGroup(t *testing.T) {
	t.Parallel()
	cleanup, conn := db.TestSetup(t, "postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewOrganization()
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		grp, err := NewGroup(s, WithDescription("this is a test group"))
		assert.Nil(err)
		assert.True(grp != nil)
		assert.Equal(grp.Description, "this is a test group")
		assert.Equal(s.PublicId, grp.ScopeId)
		err = w.Create(context.Background(), grp)
		assert.Nil(err)
		assert.True(grp.PublicId != "")
	})
	t.Run("nil-scope", func(t *testing.T) {
		grp, err := NewGroup(nil)
		assert.True(err != nil)
		assert.True(grp == nil)
		assert.Equal(err.Error(), "error the group scope is nil")
	})
}

func TestGroup_Members(t *testing.T) {
	t.Parallel()
	cleanup, conn := db.TestSetup(t, "postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
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

		grp, err := NewGroup(s, WithDescription("this is a test group"))
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

		secondUser, err := NewUser(s.PublicId)
		assert.Nil(err)
		assert.True(secondUser != nil)
		err = w.Create(context.Background(), secondUser)
		assert.Nil(err)

		gm2, err := NewGroupMember(grp, secondUser)
		assert.Nil(err)
		assert.True(gm2 != nil)
		err = w.Create(context.Background(), gm2)
		assert.Nil(err)

		members, err := grp.Members(context.Background(), &w)
		assert.Nil(err)
		assert.True(members != nil)
		assert.True(len(members) == 2)
		for _, m := range members {
			if m.GetMemberId() != secondUser.PublicId && m.GetMemberId() != user.PublicId {
				t.Errorf("members %s not one of the known ids %s, %s", m.GetMemberId(), secondUser.PublicId, user.PublicId)
			}
		}
	})
}

func TestGroup_Actions(t *testing.T) {
	assert := assert.New(t)
	r := &Group{}
	a := r.Actions()
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

func TestGroup_GetScope(t *testing.T) {
	t.Parallel()
	cleanup, conn := db.TestSetup(t, "postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewOrganization()
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		grp, err := NewGroup(s)
		assert.Nil(err)
		assert.True(grp != nil)
		assert.Equal(s.PublicId, grp.ScopeId)
		err = w.Create(context.Background(), grp)
		assert.Nil(err)
		assert.True(grp.PublicId != "")

		scope, err := grp.GetScope(context.Background(), &w)
		assert.Nil(err)
		assert.True(scope != nil)
	})
}

func TestGroup_AddMember(t *testing.T) {
	t.Parallel()
	cleanup, conn := db.TestSetup(t, "postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
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

		grp, err := NewGroup(s, WithDescription("this is a test group"))
		assert.Nil(err)
		assert.True(grp != nil)
		assert.Equal(grp.Description, "this is a test group")
		assert.Equal(s.PublicId, grp.ScopeId)
		err = w.Create(context.Background(), grp)
		assert.Nil(err)
		assert.True(grp.PublicId != "")

		gm, err := grp.AddMember(context.Background(), &w, user)
		assert.Nil(err)
		assert.True(gm != nil)
		assert.Equal(gm.(*GroupMemberUser).GroupId, grp.PublicId)
		err = w.Create(context.Background(), gm)
		assert.Nil(err)
		assert.True(gm.GetType() == "user")
	})
}

func TestGroup_Clone(t *testing.T) {
	t.Parallel()
	cleanup, conn := db.TestSetup(t, "postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewOrganization()
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		grp, err := NewGroup(s, WithDescription("this is a test group"))
		assert.Nil(err)
		assert.True(grp != nil)
		assert.Equal(grp.Description, "this is a test group")
		assert.Equal(s.PublicId, grp.ScopeId)
		err = w.Create(context.Background(), grp)
		assert.Nil(err)
		assert.True(grp.PublicId != "")

		cp := grp.Clone()
		assert.True(proto.Equal(cp.(*Group).Group, grp.Group))
	})
	t.Run("not-equal", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewOrganization()
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		grp, err := NewGroup(s, WithDescription("this is a test group"))
		assert.Nil(err)
		assert.True(grp != nil)
		assert.Equal(grp.Description, "this is a test group")
		assert.Equal(s.PublicId, grp.ScopeId)
		err = w.Create(context.Background(), grp)
		assert.Nil(err)
		assert.True(grp.PublicId != "")

		grp2, err := NewGroup(s, WithDescription("second group"))
		assert.Nil(err)
		assert.True(grp2 != nil)
		err = w.Create(context.Background(), grp2)
		assert.Nil(err)
		assert.True(grp2.PublicId != "")

		cp := grp.Clone()
		assert.True(!proto.Equal(cp.(*Group).Group, grp2.Group))
	})
}
