// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api/authtokens"
	cachedb "github.com/hashicorp/boundary/internal/clientcache/internal/db"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpsertRefreshToken(t *testing.T) {
	ctx := context.Background()

	t.Run("nil writer", func(t *testing.T) {
		err := upsertRefreshToken(ctx, nil, &user{Id: "u_123", Address: "addr"}, targetResourceType, "token")
		assert.Error(t, err)
		assert.ErrorContains(t, err, "writer is nil")
	})

	s, err := cachedb.Open(ctx)
	require.NoError(t, err)
	rw := db.New(s)

	t.Run("writer not in transaction", func(t *testing.T) {
		err = upsertRefreshToken(ctx, rw, &user{Id: "u_123", Address: "addr"}, targetResourceType, "token")
		assert.Error(t, err)
		assert.ErrorContains(t, err, "writer isn't in a transaction")
	})

	rw.DoTx(ctx, 1, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
		t.Run("user is nil", func(t *testing.T) {
			err = upsertRefreshToken(ctx, w, nil, targetResourceType, "token")
			assert.Error(t, err)
			assert.ErrorContains(t, err, "user is nil")
		})

		t.Run("user id is empty", func(t *testing.T) {
			err = upsertRefreshToken(ctx, w, &user{Address: "addr"}, targetResourceType, "token")
			assert.Error(t, err)
			assert.ErrorContains(t, err, "user id is empty")
		})

		t.Run("unknown resource type", func(t *testing.T) {
			err = upsertRefreshToken(ctx, w, &user{Id: "u_123", Address: "addr"}, unknownResourceType, "token")
			assert.Error(t, err)
			assert.ErrorContains(t, err, "resource type is invalid")
		})

		t.Run("invalid resource type", func(t *testing.T) {
			err = upsertRefreshToken(ctx, w, &user{Id: "u_123", Address: "addr"}, resourceType("this is invalid"), "token")
			assert.Error(t, err)
			assert.ErrorContains(t, err, "resource type is invalid")
		})

		t.Run("user foreign key error", func(t *testing.T) {
			err = upsertRefreshToken(ctx, w, &user{Id: "u_123", Address: "addr"}, targetResourceType, "token")
			assert.Error(t, err)
			assert.ErrorContains(t, err, "constraint failed: FOREIGN KEY")
		})

		t.Run("success upsert add", func(t *testing.T) {
			u := &user{Id: "add", Address: "addr"}
			w.Create(ctx, u)
			err = upsertRefreshToken(ctx, w, u, targetResourceType, "token")
			assert.NoError(t, err)

			rt := &refreshToken{
				UserId:       u.Id,
				ResourceType: targetResourceType,
			}
			require.NoError(t, r.LookupById(ctx, rt))
			assert.Equal(t, rt.CreateTime, rt.UpdateTime)
		})

		t.Run("success upsert update", func(t *testing.T) {
			u := &user{Id: "update", Address: "addr"}
			w.Create(ctx, u)
			err = upsertRefreshToken(ctx, w, u, targetResourceType, "token")
			assert.NoError(t, err)

			rt := &refreshToken{
				UserId:       u.Id,
				ResourceType: targetResourceType,
			}
			require.NoError(t, r.LookupById(ctx, rt))
			assert.Equal(t, rt.CreateTime, rt.UpdateTime)

			// Give sqlite's relatively low time resolution enough to see a diff
			time.Sleep(10 * time.Millisecond)

			err = upsertRefreshToken(ctx, w, u, targetResourceType, "new")
			assert.NoError(t, err)
			assert.Equal(t, "token", rt.RefreshToken)
			updatedRt := &refreshToken{
				UserId:       u.Id,
				ResourceType: targetResourceType,
			}
			require.NoError(t, r.LookupById(ctx, updatedRt))
			assert.Equal(t, "new", updatedRt.RefreshToken)
			assert.Equal(t, updatedRt.CreateTime, rt.CreateTime)
			assert.Greater(t, updatedRt.UpdateTime, updatedRt.CreateTime)
			assert.Greater(t, updatedRt.UpdateTime, rt.UpdateTime)
		})

		t.Run("success upsert delete", func(t *testing.T) {
			u := &user{Id: "delete", Address: "addr"}
			w.Create(ctx, u)
			err = upsertRefreshToken(ctx, w, u, targetResourceType, "token")
			require.NoError(t, err)
			rt := &refreshToken{
				UserId:       u.Id,
				ResourceType: targetResourceType,
			}
			require.NoError(t, r.LookupById(ctx, rt))

			// Now delete through upsert
			err = upsertRefreshToken(ctx, w, u, targetResourceType, "")
			assert.NoError(t, err)
			assert.True(t, errors.IsNotFoundError(r.LookupById(ctx, rt)))
		})

		return nil
	})
}

func TestLookupRefreshToken(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)

	r, err := NewRepository(ctx, s, &sync.Map{},
		mapBasedAuthTokenKeyringLookup(map[ringToken]*authtokens.AuthToken{}),
		sliceBasedAuthTokenBoundaryReader(nil))
	require.NoError(t, err)

	t.Run("nil user", func(t *testing.T) {
		_, err := r.lookupRefreshToken(ctx, nil, targetResourceType)
		assert.Error(t, err)
		assert.ErrorContains(t, err, "user is nil")
	})

	t.Run("user id is empty", func(t *testing.T) {
		_, err := r.lookupRefreshToken(ctx, &user{Address: "addr"}, targetResourceType)
		assert.Error(t, err)
		assert.ErrorContains(t, err, "user id is empty")
	})

	t.Run("resource type is invalid", func(t *testing.T) {
		_, err := r.lookupRefreshToken(ctx, &user{Id: "something", Address: "addr"}, resourceType("invalid"))
		assert.Error(t, err)
		assert.ErrorContains(t, err, "resource type is invalid")
	})

	t.Run("unknown user", func(t *testing.T) {
		got, err := r.lookupRefreshToken(ctx, &user{Id: "unkonwnUser", Address: "addr"}, targetResourceType)
		assert.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("no refresh token", func(t *testing.T) {
		known := &user{Id: "known", Address: "addr"}
		require.NoError(t, r.rw.Create(ctx, known))

		got, err := r.lookupRefreshToken(ctx, known, targetResourceType)
		assert.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("got refresh token", func(t *testing.T) {
		token := "something"
		known := &user{Id: "withrefreshtoken", Address: "addr"}
		require.NoError(t, r.rw.Create(ctx, known))

		r.rw.DoTx(ctx, 1, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
			require.NoError(t, upsertRefreshToken(ctx, w, known, targetResourceType, token))
			return nil
		})

		got, err := r.lookupRefreshToken(ctx, known, targetResourceType)
		assert.NoError(t, err)
		assert.Equal(t, token, got)
	})
}

func TestDeleteRefreshTokens(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)

	r, err := NewRepository(ctx, s, &sync.Map{},
		mapBasedAuthTokenKeyringLookup(map[ringToken]*authtokens.AuthToken{}),
		sliceBasedAuthTokenBoundaryReader(nil))
	require.NoError(t, err)

	t.Run("nil user", func(t *testing.T) {
		err := r.deleteRefreshToken(ctx, nil, targetResourceType)
		assert.Error(t, err)
		assert.ErrorContains(t, err, "user is nil")
	})

	t.Run("no user id", func(t *testing.T) {
		err := r.deleteRefreshToken(ctx, &user{Address: "addr"}, targetResourceType)
		assert.Error(t, err)
		assert.ErrorContains(t, err, "user id is empty")
	})

	t.Run("invalid resource type", func(t *testing.T) {
		err := r.deleteRefreshToken(ctx, &user{Id: "id", Address: "addr"}, "this is invalid")
		assert.Error(t, err)
		assert.ErrorContains(t, err, "resource type is invalid")
	})

	t.Run("success", func(t *testing.T) {
		u := &user{Id: "id", Address: "addr"}
		require.NoError(t, r.rw.Create(ctx, u))

		r.rw.DoTx(ctx, 1, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
			require.NoError(t, upsertRefreshToken(ctx, w, u, targetResourceType, "token"))
			return nil
		})
		got, err := r.lookupRefreshToken(ctx, u, targetResourceType)
		require.NoError(t, err)
		require.NotEmpty(t, got)

		assert.NoError(t, r.deleteRefreshToken(ctx, u, targetResourceType))

		got, err = r.lookupRefreshToken(ctx, u, targetResourceType)
		require.NoError(t, err)
		require.Empty(t, got)
	})
}

func TestClearExpiredRefreshTokens(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)

	r, err := NewRepository(ctx, s, &sync.Map{},
		mapBasedAuthTokenKeyringLookup(map[ringToken]*authtokens.AuthToken{}),
		sliceBasedAuthTokenBoundaryReader(nil))
	require.NoError(t, err)

	oldUser := &user{Id: "old", Address: "addr"}
	require.NoError(t, r.rw.Create(ctx, oldUser))
	newUser := &user{Id: "new", Address: "addr"}
	require.NoError(t, r.rw.Create(ctx, newUser))

	r.rw.DoTx(ctx, 1, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
		require.NoError(t, upsertRefreshToken(ctx, w, oldUser, targetResourceType, "old"))
		return nil
	})

	time.Sleep(5 * time.Second)

	r.rw.DoTx(ctx, 1, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
		require.NoError(t, upsertRefreshToken(ctx, w, oldUser, targetResourceType, "old"))
		require.NoError(t, upsertRefreshToken(ctx, w, newUser, targetResourceType, "new"))
		return nil
	})

	gotOld, err := r.lookupRefreshToken(ctx, oldUser, targetResourceType)
	require.NoError(t, err)
	assert.NotEmpty(t, gotOld)
	gotNew, err := r.lookupRefreshToken(ctx, newUser, targetResourceType)
	require.NoError(t, err)
	assert.NotEmpty(t, gotNew)

	require.NoError(t, r.clearExpiredRefreshTokens(ctx, WithDuration(time.Second)))

	gotOld, err = r.lookupRefreshToken(ctx, oldUser, targetResourceType)
	assert.NoError(t, err)
	assert.Empty(t, gotOld)

	gotNew, err = r.lookupRefreshToken(ctx, newUser, targetResourceType)
	assert.NoError(t, err)
	assert.NotEmpty(t, gotNew)
}
