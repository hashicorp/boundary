package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"gotest.tools/assert"
)

func Test_NewUser(t *testing.T) {
	db.StartTest()
	t.Parallel()
	cleanup, url := db.SetupTest(t, "../db/migrations/postgres")
	defer cleanup()
	defer db.CompleteTest() // must come after the "defer cleanup()"
	db, err := db.TestConnection(url)
	assert.NilError(t, err)
	defer db.Close()

	t.Run("valid-root", func(t *testing.T) {
		u, err := NewUser(AsRootUser(true))
		assert.NilError(t, err)
		assert.Check(t, u.User != nil)
		assert.Equal(t, u.isRootUser, true)
		assert.Equal(t, u.OwnerId, uint32(0))
	})
	t.Run("valid-WithOwnerId", func(t *testing.T) {
		u, err := NewUser(WithOwnerId(1))
		assert.NilError(t, err)
		assert.Check(t, u.User != nil)
		assert.Equal(t, u.OwnerId, uint32(1))
	})
}

func Test_UserCreate(t *testing.T) {
	db.StartTest()
	t.Parallel()
	cleanup, url := db.SetupTest(t, "../db/migrations/postgres")
	defer cleanup()
	defer db.CompleteTest() // must come after the "defer cleanup()"
	conn, err := db.TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()

	t.Run("valid root user", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		u, err := NewUser(AsRootUser(true))
		assert.NilError(t, err)
		err = w.Create(context.Background(), u)
		assert.NilError(t, err)
		assert.Check(t, u.isRootUser)
		assert.Check(t, u.Id != 0)
		assert.Equal(t, u.OwnerId, uint32(0))
	})
	t.Run("valid user with owner", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		u, err := NewUser(AsRootUser(true))
		assert.NilError(t, err)
		err = w.Create(context.Background(), u)
		assert.NilError(t, err)
		assert.Check(t, u.Id != uint32(0))

		userWithOwner, err := NewUser(WithOwnerId(u.Id))
		assert.NilError(t, err)
		err = w.Create(context.Background(), userWithOwner)
		assert.NilError(t, err)
		assert.Check(t, userWithOwner.Id != 0)
		assert.Equal(t, userWithOwner.OwnerId, u.Id)
	})
	t.Run("valid user with owner and scope", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		u, err := NewUser(AsRootUser(true))
		assert.NilError(t, err)
		err = w.Create(context.Background(), u)
		assert.NilError(t, err)
		assert.Check(t, u.Id != uint32(0))

		userWithOwner, err := NewUser(WithOwnerId(u.Id))
		assert.NilError(t, err)
		err = w.Create(context.Background(), userWithOwner)
		assert.NilError(t, err)
		assert.Check(t, userWithOwner.Id != 0)
		assert.Equal(t, userWithOwner.OwnerId, u.Id)

		s, err := NewScope(userWithOwner.Id)
		assert.NilError(t, err)
		assert.Check(t, s.Scope != nil)
		assert.Equal(t, s.Scope.OwnerId, userWithOwner.Id)

		err = w.Create(context.Background(), s)
		assert.NilError(t, err)
	})
}

func Test_UserGetPrimaryScope(t *testing.T) {
	db.StartTest()
	t.Parallel()
	cleanup, url := db.SetupTest(t, "../db/migrations/postgres")
	defer cleanup()
	defer db.CompleteTest() // must come after the "defer cleanup()"
	conn, err := db.TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()
	t.Run("valid primary scope", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		rootUser, err := NewUser(AsRootUser(true))
		assert.NilError(t, err)
		err = w.Create(context.Background(), rootUser)
		assert.NilError(t, err)
		assert.Check(t, rootUser.Id != uint32(0))

		userWithOwner, err := NewUser(WithOwnerId(rootUser.Id))
		assert.NilError(t, err)
		err = w.Create(context.Background(), userWithOwner)
		assert.NilError(t, err)
		assert.Check(t, userWithOwner.Id != 0)
		assert.Equal(t, userWithOwner.OwnerId, rootUser.Id)

		s, err := NewScope(rootUser.Id)
		assert.NilError(t, err)
		assert.Check(t, s.Scope != nil)
		assert.Equal(t, s.Scope.OwnerId, rootUser.Id)
		err = w.Create(context.Background(), s)
		assert.NilError(t, err)

		userWithOwner.PrimaryScopeId = s.Id
		err = w.Update(userWithOwner, []string{"PrimaryScopeId"})
		assert.NilError(t, err)

		primaryScope, err := userWithOwner.GetPrimaryScope(context.Background(), &w)
		assert.NilError(t, err)
		assert.Check(t, primaryScope != nil)
		assert.Equal(t, primaryScope.Id, userWithOwner.PrimaryScopeId)
	})
}
