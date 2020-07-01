package iam

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/types/resource"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func TestNewRoleGrant(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		err := cleanup()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
	}()
	t.Run("no-private-id", func(t *testing.T) {
		assert := assert.New(t)
		w := db.New(conn)
		s := testOrg(t, conn, "", "")
		role := TestRole(t, conn, s.PublicId)

		g, err := NewRoleGrant(role.PublicId, "id=*;actions=*")
		assert.NoError(err)
		assert.NotNil(g)
		err = w.Create(context.Background(), g)
		assert.Error(err)
		assert.True(errors.Is(err, db.ErrInvalidParameter), err)
	})
	t.Run("no-duplicate-grants", func(t *testing.T) {
		assert := assert.New(t)
		w := db.New(conn)
		s := testOrg(t, conn, "", "")
		role := TestRole(t, conn, s.PublicId)

		g, err := NewRoleGrant(role.PublicId, "id=*;actions=*")
		assert.NoError(err)
		assert.NotNil(g)

		g.PrivateId, err = newRoleGrantId()
		assert.NoError(err)
		err = w.Create(context.Background(), g)
		assert.NoError(err)

		g2 := g.Clone().(*RoleGrant)
		g2.PrivateId, err = newRoleGrantId()
		assert.NoError(err)
		err = w.Create(context.Background(), g2)
		assert.Error(err)
	})
	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		w := db.New(conn)
		s := testOrg(t, conn, "", "")
		role := TestRole(t, conn, s.PublicId)

		g, err := NewRoleGrant(role.PublicId, "id=*;actions=*")
		assert.NoError(err)
		assert.NotNil(g)
		assert.Equal(g.RoleId, role.PublicId)
		assert.Equal(g.Grant, "id=*;actions=*")
		g.PrivateId, err = newRoleGrantId()
		assert.NoError(err)
		err = w.Create(context.Background(), g)
		assert.NoError(err)
	})
	t.Run("nil-role", func(t *testing.T) {
		assert := assert.New(t)
		g, err := NewRoleGrant("", "id=*;actions=*")
		assert.Error(err)
		assert.Nil(g)
	})
}

func TestRoleGrant_ResourceType(t *testing.T) {
	assert := assert.New(t)
	r := &RoleGrant{}
	ty := r.ResourceType()
	assert.Equal(ty, resource.RoleGrant)
}

func TestRoleGrant_Clone(t *testing.T) {
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
		s := testOrg(t, conn, "", "")
		role := TestRole(t, conn, s.PublicId)

		g, err := NewRoleGrant(role.PublicId, "id=*;actions=*")
		assert.NoError(err)
		assert.NotNil(g)
		assert.Equal(g.RoleId, role.PublicId)
		assert.Equal(g.Grant, "id=*;actions=*")

		cp := g.Clone()
		assert.True(proto.Equal(cp.(*RoleGrant).RoleGrant, g.RoleGrant))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert := assert.New(t)
		s := testOrg(t, conn, "", "")
		role := TestRole(t, conn, s.PublicId)

		g, err := NewRoleGrant(role.PublicId, "id=*;actions=*")
		assert.NoError(err)
		assert.NotNil(g)
		assert.Equal(g.RoleId, role.PublicId)
		assert.Equal(g.Grant, "id=*;actions=*")

		g2, err := NewRoleGrant(role.PublicId, "id=foo;actions=read")
		assert.NoError(err)
		assert.NotNil(g2)
		assert.Equal(g2.RoleId, role.PublicId)
		assert.Equal(g2.Grant, "id=foo;actions=read")

		cp := g.Clone()
		assert.True(!proto.Equal(cp.(*RoleGrant).RoleGrant, g2.RoleGrant))

	})
}
