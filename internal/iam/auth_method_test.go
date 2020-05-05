package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func Test_NewAuthMethod(t *testing.T) {
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

		meth, err := NewAuthMethod(s, AuthUserPass)
		assert.Nil(err)
		assert.True(meth != nil)
		err = w.Create(context.Background(), meth)
		assert.Nil(err)
		assert.True(meth != nil)
		assert.Equal(meth.Type, AuthUserPass.String())
	})
	t.Run("nil-scope", func(t *testing.T) {
		meth, err := NewAuthMethod(nil, AuthUserPass)
		assert.True(err != nil)
		assert.True(meth == nil)
		assert.Equal(err.Error(), "error scope is nil for new auth method")
	})
}

func TestAuthMethod_GetPrimaryScope(t *testing.T) {
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

		meth, err := NewAuthMethod(s, AuthUserPass)
		assert.Nil(err)
		assert.True(meth != nil)
		err = w.Create(context.Background(), meth)
		assert.Nil(err)
		assert.True(meth != nil)
		assert.Equal(meth.Type, AuthUserPass.String())

		primaryScope, err := meth.GetPrimaryScope(context.Background(), &w)
		assert.Nil(err)
		assert.Equal(primaryScope.GetPublicId(), s.PublicId)
	})

}

func TestAuthMethod_ResourceType(t *testing.T) {
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

		meth, err := NewAuthMethod(s, AuthUserPass)
		assert.Nil(err)
		assert.True(meth != nil)
		err = w.Create(context.Background(), meth)
		assert.Nil(err)
		assert.True(meth != nil)
		assert.Equal(meth.Type, AuthUserPass.String())

		ty := meth.ResourceType()
		assert.Equal(ty, ResourceTypeAuthMethod)
	})
}

func TestAuthMethod_Actions(t *testing.T) {
	assert := assert.New(t)
	meth := &AuthMethod{}
	a := meth.Actions()
	assert.Equal(a[ActionList.String()], ActionList)
	assert.Equal(a[ActionCreate.String()], ActionCreate)
	assert.Equal(a[ActionUpdate.String()], ActionUpdate)
	assert.Equal(a[ActionRead.String()], ActionRead)
	assert.Equal(a[ActionDelete.String()], ActionDelete)
}

func TestAuthMethod_Clone(t *testing.T) {
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

		meth, err := NewAuthMethod(s, AuthUserPass)
		assert.Nil(err)
		assert.True(meth != nil)
		err = w.Create(context.Background(), meth)
		assert.Nil(err)
		assert.True(meth != nil)
		assert.Equal(meth.Type, AuthUserPass.String())

		cp := meth.Clone()
		assert.True(proto.Equal(cp.(*AuthMethod).AuthMethod, meth.AuthMethod))
	})
	t.Run("not-equal", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope(OrganizationScope)
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		meth, err := NewAuthMethod(s, AuthUserPass)
		assert.Nil(err)
		assert.True(meth != nil)
		err = w.Create(context.Background(), meth)
		assert.Nil(err)
		assert.True(meth != nil)
		assert.Equal(meth.Type, AuthUserPass.String())

		meth2, err := NewAuthMethod(s, AuthUserPass)
		assert.Nil(err)
		assert.True(meth2 != nil)
		err = w.Create(context.Background(), meth2)
		assert.Nil(err)

		cp := meth.Clone()
		assert.True(!proto.Equal(cp.(*AuthMethod).AuthMethod, meth2.AuthMethod))
	})
}
