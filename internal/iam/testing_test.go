package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/oplog"
	"github.com/stretchr/testify/assert"
)

func Test_TestVerifyOplogEntry(t *testing.T) {
	t.Parallel()
	cleanup, conn := db.TestSetup(t, "postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		rw := db.New(conn)
		wrapper := db.TestWrapper(t)
		repo, err := NewRepository(rw, rw, wrapper)
		id, err := uuid.GenerateUUID()
		assert.Nil(err)

		s, err := NewOrganization(WithName("fname-" + id))
		s, err = repo.CreateScope(context.Background(), s)
		assert.Nil(err)
		assert.True(s != nil)
		assert.True(s.GetPublicId() != "")
		assert.Equal(s.GetName(), "fname-"+id)

		foundScope, err := repo.LookupScope(context.Background(), WithPublicId(s.PublicId))
		assert.Nil(err)
		assert.Equal(foundScope.GetPublicId(), s.GetPublicId())

		foundScope, err = repo.LookupScope(context.Background(), WithName("fname-"+id))
		assert.Nil(err)
		assert.Equal(foundScope.GetPublicId(), s.GetPublicId())

		err = TestVerifyOplog(rw, s.PublicId, WithOperation(oplog.OpType_OP_TYPE_CREATE), WithCreateNbf(5))
		assert.Nil(err)
	})
	t.Run("should-fail", func(t *testing.T) {
		rw := db.New(conn)
		id, err := uuid.GenerateUUID()
		assert.Nil(err)
		err = TestVerifyOplog(rw, id)
		assert.True(err != nil)
	})
}
