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
	conn, err := db.TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()

	t.Run("valid-root-with-no-owner", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope()
		assert.NilError(t, err)
		assert.Check(t, s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NilError(t, err)
		assert.Check(t, s.Id != 0)

		rootUser, err := NewUser(s, AsRootUser(true))
		assert.NilError(t, err)
		assert.Check(t, rootUser.User != nil)
		assert.Equal(t, rootUser.isRootUser, true)
		assert.Equal(t, rootUser.OwnerId, uint32(0))
		assert.Equal(t, rootUser.PrimaryScopeId, s.Id)
	})
	t.Run("valid-WithOwnerId", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope()
		assert.NilError(t, err)
		assert.Check(t, s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NilError(t, err)
		assert.Check(t, s.Id != 0)

		rootUser, err := NewUser(s, AsRootUser(true))
		assert.NilError(t, err)
		assert.Check(t, rootUser.User != nil)
		assert.Equal(t, rootUser.isRootUser, true)
		assert.Equal(t, rootUser.OwnerId, uint32(0))
		assert.Equal(t, rootUser.PrimaryScopeId, s.Id)

		userWithOwner, err := NewUser(s, WithOwnerId(rootUser.Id))
		assert.NilError(t, err)
		assert.Check(t, userWithOwner.User != nil)
		assert.Equal(t, userWithOwner.OwnerId, rootUser.Id)
		assert.Equal(t, userWithOwner.PrimaryScopeId, s.Id)
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
		s, err := NewScope()
		assert.NilError(t, err)
		assert.Check(t, s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NilError(t, err)
		assert.Check(t, s.Id != 0)

		rootUser, err := NewUser(s, AsRootUser(true))
		assert.NilError(t, err)
		err = w.Create(context.Background(), rootUser)
		assert.NilError(t, err)
		assert.Check(t, rootUser.isRootUser)
		assert.Check(t, rootUser.Id != 0)
		assert.Equal(t, rootUser.OwnerId, uint32(0))
	})
	t.Run("valid user with owner", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope()
		assert.NilError(t, err)
		assert.Check(t, s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NilError(t, err)
		assert.Check(t, s.Id != 0)

		rootUser, err := NewUser(s, AsRootUser(true))
		assert.NilError(t, err)
		err = w.Create(context.Background(), rootUser)
		assert.NilError(t, err)
		assert.Check(t, rootUser.Id != uint32(0))

		userWithOwner, err := NewUser(s, WithOwnerId(rootUser.Id))
		assert.NilError(t, err)
		err = w.Create(context.Background(), userWithOwner)
		assert.NilError(t, err)
		assert.Check(t, userWithOwner.Id != 0)
		assert.Equal(t, userWithOwner.OwnerId, rootUser.Id)
	})
	t.Run("valid user with owner and scope", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope()
		assert.NilError(t, err)
		assert.Check(t, s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NilError(t, err)
		assert.Check(t, s.Id != 0)

		rootUser, err := NewUser(s, AsRootUser(true))
		assert.NilError(t, err)
		err = w.Create(context.Background(), rootUser)
		assert.NilError(t, err)
		assert.Check(t, rootUser.Id != uint32(0))

		userWithOwner, err := NewUser(s, WithOwnerId(rootUser.Id))
		assert.NilError(t, err)
		err = w.Create(context.Background(), userWithOwner)
		assert.NilError(t, err)
		assert.Check(t, userWithOwner.Id != 0)
		assert.Equal(t, userWithOwner.OwnerId, rootUser.Id)

		scopeWithOwner, err := NewScope(WithOwnerId(userWithOwner.Id))
		assert.NilError(t, err)
		assert.Check(t, scopeWithOwner.Scope != nil)
		assert.Equal(t, scopeWithOwner.Scope.OwnerId, userWithOwner.Id)

		err = w.Create(context.Background(), scopeWithOwner)
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
		s, err := NewScope()
		assert.NilError(t, err)
		assert.Check(t, s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NilError(t, err)
		assert.Check(t, s.Id != 0)

		rootUser, err := NewUser(s, AsRootUser(true))
		assert.NilError(t, err)
		err = w.Create(context.Background(), rootUser)
		assert.NilError(t, err)
		assert.Check(t, rootUser.Id != uint32(0))
		assert.Equal(t, rootUser.PrimaryScopeId, s.Id)

		userWithOwner, err := NewUser(s, WithOwnerId(rootUser.Id))
		assert.NilError(t, err)
		err = w.Create(context.Background(), userWithOwner)
		assert.NilError(t, err)
		assert.Check(t, userWithOwner.Id != 0)
		assert.Equal(t, userWithOwner.OwnerId, rootUser.Id)

		scopeWithOwner, err := NewScope(WithOwnerId(rootUser.Id))
		assert.NilError(t, err)
		assert.Check(t, scopeWithOwner.Scope != nil)
		assert.Equal(t, scopeWithOwner.Scope.OwnerId, rootUser.Id)
		err = w.Create(context.Background(), scopeWithOwner)
		assert.NilError(t, err)

		userWithOwner.PrimaryScopeId = scopeWithOwner.Id
		err = w.Update(context.Background(), userWithOwner, []string{"PrimaryScopeId"})
		assert.NilError(t, err)

		primaryScope, err := userWithOwner.GetPrimaryScope(context.Background(), &w)
		assert.NilError(t, err)
		assert.Check(t, primaryScope != nil)
		assert.Equal(t, primaryScope.Id, userWithOwner.PrimaryScopeId)
	})

}

func Test_UserGetOwner(t *testing.T) {
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
		s, err := NewScope()
		assert.NilError(t, err)
		assert.Check(t, s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NilError(t, err)
		assert.Check(t, s.Id != 0)

		rootUser, err := NewUser(s, AsRootUser(true))
		assert.NilError(t, err)
		err = w.Create(context.Background(), rootUser)
		assert.NilError(t, err)
		assert.Check(t, rootUser.Id != uint32(0))
		assert.Equal(t, rootUser.PrimaryScopeId, s.Id)

		userWithOwner, err := NewUser(s, WithOwnerId(rootUser.Id))
		assert.NilError(t, err)
		err = w.Create(context.Background(), userWithOwner)
		assert.NilError(t, err)
		assert.Check(t, userWithOwner.Id != 0)
		assert.Equal(t, userWithOwner.OwnerId, rootUser.Id)

		owner, err := userWithOwner.GetOwner(context.Background(), &w)
		assert.NilError(t, err)
		assert.Equal(t, owner.Id, rootUser.Id)
	})

}
