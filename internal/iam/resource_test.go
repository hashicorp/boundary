package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func Test_LookupScope(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()
	t.Run("valid-scope", func(t *testing.T) {
		w := db.New(conn)
		org, _ := TestScopes(t, conn)
		user := TestUser(t, conn, org.PublicId)

		foundScope, err := LookupScope(context.Background(), w, user)
		assert.NoError(err)
		assert.Equal(foundScope.PublicId, user.ScopeId)

		user2 := allocUser()
		user2.PublicId = user.PublicId
		foundScope, err = LookupScope(context.Background(), w, user)
		assert.NoError(err)
		assert.True(proto.Equal(foundScope, org))
	})
	t.Run("bad-scope", func(t *testing.T) {
		w := db.New(conn)
		org, _ := TestScopes(t, conn)
		user := TestUser(t, conn, org.PublicId)

		s, err := LookupScope(context.Background(), nil, user)
		assert.Nil(s)
		assert.Equal("error reader is nil for LookupScope", err.Error())

		s, err = LookupScope(context.Background(), w, nil)
		assert.Nil(s)
		assert.Equal("error resource is nil for LookupScope", err.Error())

		user2 := allocUser()
		s, err = LookupScope(context.Background(), w, &user2)
		assert.Nil(s)
		assert.Equal("error resource has an unset public id", err.Error())

	})
}
