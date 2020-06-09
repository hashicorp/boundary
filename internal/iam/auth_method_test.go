package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func Test_NewAuthMethod(t *testing.T) {
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

		meth, err := NewAuthMethod(s.PublicId, AuthUserPass)
		assert.NoError(err)
		assert.NotNil(meth)
		err = w.Create(context.Background(), meth)
		assert.NoError(err)
		assert.NotNil(meth)
		assert.Equal(meth.Type, AuthUserPass.String())
	})
	t.Run("no-scope", func(t *testing.T) {
		assert := assert.New(t)
		meth, err := NewAuthMethod("", AuthUserPass)
		assert.Error(err)
		assert.Nil(meth)
		assert.Equal(err.Error(), "error organization id is unset for new auth method")
	})
}

func TestAuthMethod_GetScope(t *testing.T) {
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

		meth, err := NewAuthMethod(s.PublicId, AuthUserPass)
		assert.NoError(err)
		assert.NotNil(meth)
		err = w.Create(context.Background(), meth)
		assert.NoError(err)
		assert.NotNil(meth)
		assert.Equal(meth.Type, AuthUserPass.String())

		scope, err := meth.GetScope(context.Background(), w)
		assert.NoError(err)
		assert.Equal(scope.GetPublicId(), s.PublicId)
	})
}

func TestAuthMethod_ResourceType(t *testing.T) {
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

		meth, err := NewAuthMethod(s.PublicId, AuthUserPass)
		assert.NoError(err)
		assert.NotNil(meth)
		err = w.Create(context.Background(), meth)
		assert.NoError(err)
		assert.NotNil(meth)
		assert.Equal(meth.Type, AuthUserPass.String())

		ty := meth.ResourceType()
		assert.Equal(ty, ResourceTypeAuthMethod)
	})
}

func TestAuthMethod_Actions(t *testing.T) {
	assert := assert.New(t)
	meth := &AuthMethod{}
	a := meth.Actions()
	assert.Equal(a[ActionCreate.String()], ActionCreate)
	assert.Equal(a[ActionUpdate.String()], ActionUpdate)
	assert.Equal(a[ActionRead.String()], ActionRead)
	assert.Equal(a[ActionDelete.String()], ActionDelete)
}

func TestAuthMethod_Clone(t *testing.T) {
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

		meth, err := NewAuthMethod(s.PublicId, AuthUserPass)
		assert.NoError(err)
		assert.NotNil(meth)
		err = w.Create(context.Background(), meth)
		assert.NoError(err)
		assert.NotNil(meth)
		assert.Equal(meth.Type, AuthUserPass.String())

		cp := meth.Clone()
		assert.True(proto.Equal(cp.(*AuthMethod).AuthMethod, meth.AuthMethod))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert := assert.New(t)
		w := db.New(conn)
		s := testOrg(t, conn, "", "")

		meth, err := NewAuthMethod(s.PublicId, AuthUserPass)
		assert.NoError(err)
		assert.NotNil(meth)
		err = w.Create(context.Background(), meth)
		assert.NoError(err)
		assert.NotNil(meth)
		assert.Equal(meth.Type, AuthUserPass.String())

		meth2, err := NewAuthMethod(s.PublicId, AuthUserPass)
		assert.NoError(err)
		assert.NotNil(meth2)
		err = w.Create(context.Background(), meth2)
		assert.NoError(err)

		cp := meth.Clone()
		assert.True(!proto.Equal(cp.(*AuthMethod).AuthMethod, meth2.AuthMethod))
	})
}
