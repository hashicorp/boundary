package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func Test_LookupScope(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		err := cleanup()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
	}()
	t.Run("valid-scope", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := db.New(conn)
		org, _ := TestScopes(t, conn)
		user := TestUser(t, conn, org.PublicId)

		foundScope, err := LookupScope(context.Background(), w, user)
		require.NoError(err)
		assert.Equal(foundScope.PublicId, user.ScopeId)

		user2 := allocUser()
		user2.PublicId = user.PublicId
		foundScope, err = LookupScope(context.Background(), w, user)
		require.NoError(err)
		assert.True(proto.Equal(foundScope, org))
	})
	t.Run("bad-scope", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := db.New(conn)
		org, _ := TestScopes(t, conn)
		user := TestUser(t, conn, org.PublicId)

		s, err := LookupScope(context.Background(), nil, user)
		require.Error(err)
		assert.Nil(s)
		assert.Equal("error reader is nil for LookupScope", err.Error())

		s, err = LookupScope(context.Background(), w, nil)
		assert.Nil(s)
		assert.Equal("error resource is nil for LookupScope", err.Error())

		user2 := allocUser()
		s, err = LookupScope(context.Background(), w, &user2)
		assert.Nil(s)
		assert.Equal("LookupScope: scope id is unset invalid parameter", err.Error())
	})
}
