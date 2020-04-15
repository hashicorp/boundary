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

	t.Run("valid", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		u, err := NewUser(AsRootUser(true))
		if err != nil {
			t.Fatal(err)
		}
		w.Create(context.Background(), u)
		assert.Check(t, u.Id != 0)

		s, err := NewScope(u.Id)
		assert.NilError(t, err)
		assert.Check(t, s.Scope != nil)
		assert.Equal(t, s.Scope.OwnerId, u.Id)
	})
	t.Run("bad-owner", func(t *testing.T) {
		_, err := NewScope(0)
		assert.Check(t, err != nil)
		assert.Equal(t, err.Error(), "error ownerId is 0 for NewScope")
	})
}
func Test_ScopeWrite(t *testing.T) {
	db.StartTest()
	t.Parallel()
	cleanup, url := db.SetupTest(t, "../db/migrations/postgres")
	defer cleanup()
	defer db.CompleteTest() // must come after the "defer cleanup()"
	conn, err := db.TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		w := db.GormReadWriter{Tx: conn}
		u, err := NewUser(AsRootUser(true))
		if err != nil {
			t.Fatal(err)
		}
		w.Create(context.Background(), u)
		assert.Check(t, u.Id != 0)

		s, err := NewScope(u.Id)
		assert.NilError(t, err)
		assert.Check(t, s.Scope != nil)
		assert.Equal(t, s.Scope.OwnerId, u.Id)

		err = w.Create(context.Background(), s)
		assert.NilError(t, err)
	})

}
