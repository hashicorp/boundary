// Copyright IBM Corp. 2020, 2025
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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListRefreshToken(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)

	r, err := NewRepository(ctx, s, &sync.Map{},
		mapBasedAuthTokenKeyringLookup(map[ringToken]*authtokens.AuthToken{}),
		sliceBasedAuthTokenBoundaryReader(nil))
	require.NoError(t, err)

	t.Run("nil user", func(t *testing.T) {
		got, err := r.listRefreshTokens(ctx, nil)
		assert.ErrorContains(t, err, "user is nil")
		assert.Nil(t, got)
	})
	t.Run("empty user id", func(t *testing.T) {
		got, err := r.listRefreshTokens(ctx, &user{Address: ""})
		assert.ErrorContains(t, err, "user id is empty")
		assert.Nil(t, got)
	})
	t.Run("empty response", func(t *testing.T) {
		got, err := r.listRefreshTokens(ctx, &user{Id: "u123"})
		assert.NoError(t, err)
		assert.Empty(t, got)
	})
	t.Run("got target response", func(t *testing.T) {
		known := &user{Id: "withtargetresponse", Address: "addr"}
		require.NoError(t, r.rw.Create(ctx, known))

		token := RefreshTokenValue("something")
		_, err = r.rw.DoTx(ctx, 1, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
			require.NoError(t, upsertRefreshToken(ctx, w, known, targetResourceType, token))
			return nil
		})
		require.NoError(t, err)

		got, err := r.listRefreshTokens(ctx, known)
		assert.NoError(t, err)
		assert.Len(t, got, 1)
	})
	t.Run("sentinel values", func(t *testing.T) {
		known := &user{Id: "sentinelValues", Address: "addr"}
		require.NoError(t, r.rw.Create(ctx, known))

		token := sentinelNoRefreshToken
		_, err = r.rw.DoTx(ctx, 1, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
			require.NoError(t, upsertRefreshToken(ctx, w, known, targetResourceType, token))
			return nil
		})
		require.NoError(t, err)

		got, err := r.listRefreshTokens(ctx, known)
		assert.NoError(t, err)
		assert.Empty(t, got)
	})
	t.Run("got multiple responses", func(t *testing.T) {
		known := &user{Id: "with multiple responses", Address: "addr"}
		require.NoError(t, r.rw.Create(ctx, known))

		token := RefreshTokenValue("something")
		_, err := r.rw.DoTx(ctx, 1, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
			require.NoError(t, upsertRefreshToken(ctx, w, known, targetResourceType, token))
			require.NoError(t, upsertRefreshToken(ctx, w, known, sessionResourceType, token))
			return nil
		})
		require.NoError(t, err)

		got, err := r.listRefreshTokens(ctx, known)
		assert.NoError(t, err)
		assert.Len(t, got, 2)
	})
}

func TestCacheSupportState(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)

	r, err := NewRepository(ctx, s, &sync.Map{},
		mapBasedAuthTokenKeyringLookup(map[ringToken]*authtokens.AuthToken{}),
		sliceBasedAuthTokenBoundaryReader(nil))
	require.NoError(t, err)

	t.Run("unknown", func(t *testing.T) {
		known := &user{Id: "unknown", Address: "addr"}
		require.NoError(t, r.rw.Create(ctx, known))

		got, err := r.listRefreshTokens(ctx, known)
		assert.NoError(t, err)
		assert.Empty(t, got)

		cs, err := r.cacheSupportState(ctx, known)
		assert.NoError(t, err)
		assert.Equal(t, cs.supported, UnknownCacheSupport)
		assert.Nil(t, cs.lastChecked)
	})

	t.Run("unsupported", func(t *testing.T) {
		known := &user{Id: "unsupported", Address: "addr"}
		require.NoError(t, r.rw.Create(ctx, known))

		now := time.Now().Truncate(time.Millisecond)
		token := sentinelNoRefreshToken
		_, err = r.rw.DoTx(ctx, 1, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
			require.NoError(t, upsertRefreshToken(ctx, w, known, targetResourceType, token))
			return nil
		})
		require.NoError(t, err)

		got, err := r.listRefreshTokens(ctx, known)
		assert.NoError(t, err)
		assert.Empty(t, got)

		cs, err := r.cacheSupportState(ctx, known)
		assert.NoError(t, err)
		assert.Equal(t, cs.supported, NotSupportedCacheSupport)
		assert.NotNil(t, cs.lastChecked)
		assert.LessOrEqual(t, now, *cs.lastChecked)
	})

	t.Run("Supported", func(t *testing.T) {
		known := &user{Id: "supported", Address: "addr"}
		require.NoError(t, r.rw.Create(ctx, known))

		now := time.Now().Truncate(time.Millisecond)
		token := RefreshTokenValue("something")
		r.rw.DoTx(ctx, 1, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
			require.NoError(t, upsertRefreshToken(ctx, w, known, targetResourceType, token))
			require.NoError(t, upsertRefreshToken(ctx, w, known, sessionResourceType, token))
			return nil
		})

		got, err := r.listRefreshTokens(ctx, known)
		assert.NoError(t, err)
		assert.Len(t, got, 2)

		cs, err := r.cacheSupportState(ctx, known)
		assert.NoError(t, err)
		assert.Equal(t, cs.supported, SupportedCacheSupport)
		assert.NotNil(t, cs.lastChecked)
		assert.LessOrEqual(t, now, *cs.lastChecked)
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
		got, err := r.lookupRefreshToken(ctx, &user{Id: "unknownUser", Address: "addr"}, targetResourceType)
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
		token := RefreshTokenValue("something")
		known := &user{Id: "withrefreshtoken", Address: "addr"}
		require.NoError(t, r.rw.Create(ctx, known))

		before := time.Now().Truncate(time.Millisecond).UTC()
		_, err := r.rw.DoTx(ctx, 1, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
			require.NoError(t, upsertRefreshToken(ctx, w, known, targetResourceType, token))
			return nil
		})
		require.NoError(t, err)

		got, err := r.lookupRefreshToken(ctx, known, targetResourceType)
		assert.NoError(t, err)
		assert.Equal(t, token, got.RefreshToken)
		assert.GreaterOrEqual(t, got.CreateTime, before)
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
