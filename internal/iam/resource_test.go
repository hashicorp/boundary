package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
)

func Test_LookupScope(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer cleanup()
	assert := assert.New(t)
	defer conn.Close()
	t.Run("valid-scope", func(t *testing.T) {
		w := db.New(conn)
		s, err := NewOrganization()
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		user, err := NewUser(s.PublicId)
		assert.Nil(err)
		err = w.Create(context.Background(), user)
		assert.Nil(err)
		assert.True(user.PublicId != "")
		assert.Equal(user.ScopeId, s.PublicId)

		foundScope, err := LookupScope(context.Background(), w, user)
		assert.Nil(err)
		assert.Equal(foundScope.PublicId, user.ScopeId)

		user2 := allocUser()
		user2.PublicId = user.PublicId
		foundScope, err = LookupScope(context.Background(), w, user)
		assert.Nil(err)
		assert.Equal(foundScope.PublicId, user.ScopeId)
	})
	t.Run("bad-scope", func(t *testing.T) {
		w := db.New(conn)

		s, err := NewOrganization()
		assert.Nil(err)
		assert.True(s.Scope != nil)
		err = w.Create(context.Background(), s)
		assert.Nil(err)
		assert.True(s.PublicId != "")

		user, err := NewUser(s.PublicId)
		assert.Nil(err)
		err = w.Create(context.Background(), user)
		assert.Nil(err)
		assert.True(user.PublicId != "")
		assert.Equal(user.ScopeId, s.PublicId)

		r, err := LookupScope(context.Background(), w, nil)
		assert.True(r == nil)
		assert.Equal("error resource is nil for LookupScope", err.Error())

		r, err = LookupScope(context.Background(), nil, user)
		assert.True(r == nil)
		assert.Equal("error reader is nil for LookupScope", err.Error())

		user2 := allocUser()
		r, err = LookupScope(context.Background(), w, &user2)
		assert.True(r == nil)
		assert.Equal("error resource has an unset public id", err.Error())

	})
}
