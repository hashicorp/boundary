package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func Test_Repository_CreateUser(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid", func(t *testing.T) {
		rw := db.New(conn)
		wrapper := db.TestWrapper(t)
		repo, err := NewRepository(rw, rw, wrapper)
		id, err := uuid.GenerateUUID()
		assert.NoError(err)

		s, err := NewOrganization()
		s, err = repo.CreateScope(context.Background(), s)
		assert.NoError(err)
		assert.NotNil(s)

		u, err := NewUser(s.PublicId, WithName("fn-"+id))
		assert.NoError(err)
		assert.Equal(s.GetPublicId(), u.ScopeId)
		assert.Equal(u.GetName(), "fn-"+id)

		u, err = repo.CreateUser(context.Background(), u)
		assert.NoError(err)
		assert.NotNil(u.CreateTime)
		assert.NotNil(u.UpdateTime)

		foundUser, err := repo.LookupUser(context.Background(), u.PublicId)
		assert.NoError(err)
		assert.True(proto.Equal(foundUser, u))

		err = db.TestVerifyOplog(rw, u.PublicId)
		assert.NoError(err)
	})
	t.Run("bad-scope-id", func(t *testing.T) {
		rw := db.New(conn)
		wrapper := db.TestWrapper(t)
		repo, err := NewRepository(rw, rw, wrapper)
		badScopeId, err := uuid.GenerateUUID()
		assert.NoError(err)
		u, err := NewUser(badScopeId)
		assert.NoError(err)
		assert.Equal(badScopeId, u.ScopeId)

		pubId := u.PublicId
		u, err = repo.CreateUser(context.Background(), u)
		assert.Error(err)
		assert.Nil(u)
		// not convinced this is what we want for an error msg,
		// but it does show the chain of errors
		assert.Equal("failed to create user: error getting metadata for create: unable to get scope for standard metadata: error getting scope for LookupScope: record not found", err.Error())

		foundUser, err := repo.LookupUser(context.Background(), pubId)
		assert.NotNil(err)
		assert.Nil(foundUser)

		err = db.TestVerifyOplog(rw, pubId)
		assert.Error(err)
	})
}
