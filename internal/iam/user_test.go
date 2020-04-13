package iam

import (
	"context"
	"testing"

	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"gotest.tools/assert"
)

func Test_NewUser(t *testing.T) {
	startTest()
	t.Parallel()
	cleanup, url := setup(t)
	defer cleanup()
	defer completeTest() // must come after the "defer cleanup()"
	db, err := test_dbconn(url)
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

func Test_UserWrite(t *testing.T) {
	startTest()
	t.Parallel()
	cleanup, url := setup(t)
	defer cleanup()
	defer completeTest() // must come after the "defer cleanup()"
	db, err := test_dbconn(url)
	assert.NilError(t, err)
	defer db.Close()

	t.Run("valid root user", func(t *testing.T) {
		w := GormReadWriter{Tx: db}
		u, err := NewUser(AsRootUser(true))
		assert.NilError(t, err)
		err = u.Write(context.Background(), &w)
		assert.NilError(t, err)
		assert.Check(t, u.isRootUser)
		assert.Check(t, u.Id != 0)
		assert.Equal(t, u.OwnerId, uint32(0))
	})
	t.Run("valid user with owner", func(t *testing.T) {
		w := GormReadWriter{Tx: db}
		u, err := NewUser(AsRootUser(true))
		assert.NilError(t, err)
		err = u.Write(context.Background(), &w)
		assert.NilError(t, err)
		assert.Check(t, u.Id != uint32(0))

		userWithOwner, err := NewUser(WithOwnerId(u.Id))
		assert.NilError(t, err)
		err = userWithOwner.Write(context.Background(), &w)
		assert.NilError(t, err)
		assert.Check(t, userWithOwner.Id != 0)
		assert.Equal(t, userWithOwner.OwnerId, u.Id)
	})
}
