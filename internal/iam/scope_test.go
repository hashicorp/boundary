package iam

import (
	"context"
	"testing"

	"gotest.tools/assert"
)

func Test_NewScope(t *testing.T) {
	startTest()
	t.Parallel()
	cleanup, url := setup(t)
	defer cleanup()
	defer completeTest() // must come after the "defer cleanup()"
	db, err := test_dbconn(url)
	assert.NilError(t, err)
	defer db.Close()

	t.Run("valid", func(t *testing.T) {
		w := GormReadWriter{Tx: db}
		u, err := NewUser(AsRootUser(true))
		if err != nil {
			t.Fatal(err)
		}
		u.Write(context.Background(), &w)
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
	startTest()
	t.Parallel()
	cleanup, url := setup(t)
	defer cleanup()
	defer completeTest() // must come after the "defer cleanup()"
	db, err := test_dbconn(url)
	assert.NilError(t, err)
	defer db.Close()

	t.Run("valid", func(t *testing.T) {
		w := GormReadWriter{Tx: db}
		u, err := NewUser(AsRootUser(true))
		if err != nil {
			t.Fatal(err)
		}
		u.Write(context.Background(), &w)
		assert.Check(t, u.Id != 0)

		s, err := NewScope(u.Id)
		assert.NilError(t, err)
		assert.Check(t, s.Scope != nil)
		assert.Equal(t, s.Scope.OwnerId, u.Id)

		err = s.Write(context.Background(), &w)
		assert.NilError(t, err)
	})

}
