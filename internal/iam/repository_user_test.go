package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/oplog"
	"github.com/hashicorp/watchtower/internal/oplog/store"
	"github.com/stretchr/testify/assert"
)

func Test_Repository_CreateUser(t *testing.T) {
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

		s, err := NewOrganization()
		s, err = repo.CreateScope(context.Background(), s)
		assert.Nil(err)
		assert.True(s != nil)

		u, err := NewUser(s.PublicId, WithName("fn-"+id))
		assert.Nil(err)
		assert.Equal(s.GetPublicId(), u.ScopeId)
		assert.Equal(u.GetName(), "fn-"+id)

		u, err = repo.CreateUser(context.Background(), u)
		assert.Nil(err)
		assert.True(u.CreateTime != nil)
		assert.True(u.UpdateTime != nil)

		foundUser, err := repo.LookupUser(context.Background(), WithPublicId(u.PublicId))
		assert.Nil(err)
		assert.Equal(foundUser.GetPublicId(), u.GetPublicId())
		assert.Equal(foundUser.GetScopeId(), u.GetScopeId())
		assert.Equal(foundUser.GetName(), "fn-"+id)

		var metadata store.Metadata
		err = conn.Where("key = ? and value = ?", "resource-public-id", u.PublicId).First(&metadata).Error
		assert.Nil(err)

		var foundEntry oplog.Entry
		err = conn.Where("id = ?", metadata.EntryId).First(&foundEntry).Error
		assert.Nil(err)
	})
	t.Run("bad-scope-id", func(t *testing.T) {
		rw := db.New(conn)
		wrapper := db.TestWrapper(t)
		repo, err := NewRepository(rw, rw, wrapper)
		badScopeId, err := uuid.GenerateUUID()
		assert.Nil(err)
		u, err := NewUser(badScopeId)
		assert.Nil(err)
		assert.Equal(badScopeId, u.ScopeId)

		pubId := u.PublicId
		u, err = repo.CreateUser(context.Background(), u)
		assert.True(err != nil)
		assert.True(u == nil)
		// not convinced this is what we want for an error msg,
		// but it does show the chain of errors
		assert.Equal("failed to create user: error getting metadata for create: unable to get scope for standard metadata: error getting scope for LookupScope: record not found", err.Error())

		foundUser, err := repo.LookupUser(context.Background(), WithPublicId(pubId))
		assert.True(err != nil)
		assert.True(foundUser == nil)

		var metadata store.Metadata
		err = conn.Where("key = ? and value = ?", "resource-public-id", pubId).First(&metadata).Error
		assert.True(err != nil)

	})
}
