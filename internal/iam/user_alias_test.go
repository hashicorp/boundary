package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/watchtower/internal/db"
	"gotest.tools/assert"
)

func Test_NewUserAlias(t *testing.T) {
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
		s, err := NewScope(OrganizationScope)
		assert.NilError(t, err)
		assert.Check(t, s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.NilError(t, err)
		assert.Check(t, s.Id != 0)

		rootUser, err := NewUser(s, AsRootUser(true))
		assert.NilError(t, err)
		err = w.Create(context.Background(), rootUser)
		assert.NilError(t, err)

		meth, err := NewAuthMethod(s, rootUser, AuthUserPass)
		assert.NilError(t, err)
		assert.Check(t, meth != nil)
		err = w.Create(context.Background(), meth)
		assert.NilError(t, err)

		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)
		alias, err := NewUserAlias(s, rootUser, meth, id)
		assert.NilError(t, err)
		assert.Check(t, alias != nil)
		err = w.Create(context.Background(), alias)
		assert.NilError(t, err)
		assert.Check(t, alias != nil)
		assert.Equal(t, alias.OwnerId, rootUser.Id)
	})
}
