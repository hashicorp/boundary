package db

import (
	"context"
	"reflect"
	"testing"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/watchtower/internal/db/db_test"
	"github.com/hashicorp/watchtower/internal/oplog"
	"github.com/stretchr/testify/assert"
)

func Test_Utils(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := TestSetup(t, "postgres")
	defer cleanup()
	defer conn.Close()
	t.Run("nothing", func(t *testing.T) {

	})
}

func Test_TestVerifyOplogEntry(t *testing.T) {
	cleanup, db, _ := TestSetup(t, "postgres")
	defer cleanup()
	assert := assert.New(t)
	defer db.Close()

	t.Run("valid", func(t *testing.T) {
		rw := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)
		user, err := db_test.NewTestUser()
		assert.Nil(err)
		user.Name = "foo-" + id
		err = rw.Create(context.Background(), user)
		assert.Nil(err)
		assert.True(user.Id != 0)

		foundUser, err := db_test.NewTestUser()
		assert.Nil(err)
		foundUser.PublicId = user.PublicId
		err = rw.LookupByPublicId(context.Background(), foundUser)
		assert.Nil(err)
		assert.Equal(foundUser.Id, user.Id)

		err = TestVerifyOplog(&rw, user.PublicId, WithOperation(oplog.OpType_OP_TYPE_CREATE), WithCreateNbf(5))
		assert.Nil(err)
	})
	t.Run("should-fail", func(t *testing.T) {
		rw := Db{underlying: db}
		id, err := uuid.GenerateUUID()
		assert.Nil(err)
		err = TestVerifyOplog(&rw, id)
		assert.True(err != nil)
	})
}

func Test_getTestOpts(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	t.Run("WithOperation", func(t *testing.T) {
		opts := getTestOpts(WithOperation(oplog.OpType_OP_TYPE_CREATE))
		testOpts := getDefaultTestOptions()
		testOpts.withOperation = oplog.OpType_OP_TYPE_CREATE
		assert.True(reflect.DeepEqual(opts, testOpts))
	})
	t.Run("WithCreateNbf", func(t *testing.T) {
		nbfSecs := 10
		opts := getTestOpts(WithCreateNbf(nbfSecs))
		testOpts := getDefaultTestOptions()
		testOpts.withCreateNbf = &nbfSecs
		assert.True(reflect.DeepEqual(opts, testOpts))
	})
}
