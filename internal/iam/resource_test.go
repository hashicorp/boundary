// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func Test_LookupScope(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	t.Run("valid-scope", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := db.New(conn)
		org, _ := TestScopes(t, repo)
		user := TestUser(t, repo, org.PublicId)

		foundScope, err := LookupScope(context.Background(), w, user)
		require.NoError(err)
		assert.Equal(foundScope.PublicId, user.ScopeId)

		user2 := AllocUser()
		user2.PublicId = user.PublicId
		foundScope, err = LookupScope(context.Background(), w, user)
		require.NoError(err)
		assert.True(proto.Equal(foundScope, org))
	})
	t.Run("bad-scope", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		w := db.New(conn)
		org, _ := TestScopes(t, repo)
		user := TestUser(t, repo, org.PublicId)

		s, err := LookupScope(context.Background(), nil, user)
		require.Error(err)
		assert.Nil(s)
		assert.Equal("iam.LookupScope: nil reader: parameter violation: error #100", err.Error())

		s, err = LookupScope(context.Background(), w, nil)
		assert.Nil(s)
		assert.Equal("iam.LookupScope: missing resource: parameter violation: error #100", err.Error())

		user2 := AllocUser()
		s, err = LookupScope(context.Background(), w, &user2)
		assert.Nil(s)
		assert.Contains(err.Error(), "iam.LookupScope: missing public id: parameter violation: error #100")
	})
}
