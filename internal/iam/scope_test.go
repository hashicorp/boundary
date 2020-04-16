package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"gotest.tools/assert"
)

func Test_NewScope(t *testing.T) {
	db.StartTest()
	t.Parallel()
	cleanup, url := db.SetupTest(t, "../db/migrations/postgres")
	defer cleanup()
	defer db.CompleteTest() // must come after the "defer cleanup()"
	conn, err := db.TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()

	t.Run("valid-with-owner", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope()
		assert.NilError(t, err)
		assert.Check(t, s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NilError(t, err)
		assert.Check(t, s.Id != 0)

		rootUser, err := NewUser(s, AsRootUser(true))
		assert.NilError(t, err)
		w.Create(context.Background(), rootUser)
		assert.NilError(t, err)
		assert.Check(t, rootUser.Id != 0)

		scopeWithOwner, err := NewScope(WithOwnerId(rootUser.Id))
		assert.NilError(t, err)
		assert.Check(t, scopeWithOwner.Scope != nil)
		assert.Equal(t, scopeWithOwner.Scope.OwnerId, rootUser.Id)
	})
	t.Run("no-owner", func(t *testing.T) {
		s, err := NewScope()
		assert.NilError(t, err)
		assert.Equal(t, s.OwnerId, uint32(0))
	})
}
func Test_ScopeCreate(t *testing.T) {
	db.StartTest()
	t.Parallel()
	cleanup, url := db.SetupTest(t, "../db/migrations/postgres")
	defer cleanup()
	defer db.CompleteTest() // must come after the "defer cleanup()"
	conn, err := db.TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()

	t.Run("valid-no-owner", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope()
		assert.NilError(t, err)
		assert.Check(t, s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NilError(t, err)
		assert.Check(t, s.Id != 0)
	})
	t.Run("valid-with-owner", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		s, err := NewScope()
		assert.NilError(t, err)
		assert.Check(t, s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NilError(t, err)
		assert.Check(t, s.Id != 0)

		rootUser, err := NewUser(s, AsRootUser(true))
		assert.NilError(t, err)
		w.Create(context.Background(), rootUser)
		assert.NilError(t, err)
		assert.Check(t, rootUser.Id != 0)

		scopeWithOwner, err := NewScope(WithOwnerId(rootUser.Id))
		assert.NilError(t, err)
		assert.Check(t, scopeWithOwner.Scope != nil)
		assert.Equal(t, scopeWithOwner.Scope.OwnerId, rootUser.Id)

		err = w.Create(context.Background(), scopeWithOwner)
		assert.NilError(t, err)
		assert.Equal(t, scopeWithOwner.OwnerId, rootUser.Id)

	})
}

func Test_ScopeGetOwner(t *testing.T) {
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

		scopeWithOwner, err := NewScope(WithOwnerId(rootUser.Id))
		assert.NilError(t, err)
		assert.Check(t, scopeWithOwner.Scope != nil)
		assert.Equal(t, scopeWithOwner.Scope.OwnerId, rootUser.Id)
		err = w.Create(context.Background(), scopeWithOwner)
		assert.NilError(t, err)

		owner, err := scopeWithOwner.GetOwner(context.Background(), &w)
		assert.NilError(t, err)
		assert.Equal(t, owner.Id, rootUser.Id)
	})
}

func Test_ScopeGetPrimaryScope(t *testing.T) {
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

		scopeWithOwner, err := NewScope(WithOwnerId(rootUser.Id), WithScope(s))
		assert.NilError(t, err)
		assert.Check(t, scopeWithOwner.Scope != nil)
		assert.Equal(t, scopeWithOwner.OwnerId, rootUser.Id)
		err = w.Create(context.Background(), scopeWithOwner)
		assert.NilError(t, err)

		primaryScope, err := scopeWithOwner.GetPrimaryScope(context.Background(), &w)
		assert.NilError(t, err)
		assert.Check(t, primaryScope != nil)
		// assert.Equal(t, primaryScope.Id, scopeWithOwner.ParentId)
	})

}
