// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	stdErrors "errors"
	"fmt"
	"sync"
	"testing"

	"github.com/hashicorp/boundary/api/authtokens"
	cachedb "github.com/hashicorp/boundary/internal/clientcache/internal/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ringToken is a test struct used to group a keyring type and token name
// so it can be used in an authtoken lookup function.
type ringToken struct {
	k string
	t string
}

// mapBasedAuthTokenKeyringLookup provides a fake KeyringTokenLookupFn that uses
// the provided map to perform lookups for the tokens
func mapBasedAuthTokenKeyringLookup(m map[ringToken]*authtokens.AuthToken) KeyringTokenLookupFn {
	return func(k, t string) (*authtokens.AuthToken, error) {
		return m[ringToken{k, t}], nil
	}
}

// sliceBasedAuthTokenBoundaryReader provides a fake BoundaryTokenReaderFn that uses
// the provided map to lookup an auth tokens information.
func sliceBasedAuthTokenBoundaryReader(s []*authtokens.AuthToken) BoundaryTokenReaderFn {
	return func(ctx context.Context, addr, at string) (*authtokens.AuthToken, error) {
		for _, v := range s {
			if at == v.Token {
				return v, nil
			}
		}
		return nil, stdErrors.New("not found")
	}
}

func TestRepository_saveError(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)

	r, err := NewRepository(ctx, s, &sync.Map{},
		mapBasedAuthTokenKeyringLookup(map[ringToken]*authtokens.AuthToken{}),
		sliceBasedAuthTokenBoundaryReader(nil))
	require.NoError(t, err)

	testResource := targetResourceType
	testErr := fmt.Errorf("test error for %q", testResource)

	u := &user{
		Id:      "u1",
		Address: "addr",
	}
	require.NoError(t, r.rw.Create(ctx, u))

	t.Run("empty resource type", func(t *testing.T) {
		assert.ErrorContains(t, r.saveError(ctx, u, "", testErr), "resource type is invalid")
	})
	t.Run("nil error", func(t *testing.T) {
		assert.ErrorContains(t, r.saveError(ctx, u, testResource, nil), "error is nil")
	})
	t.Run("nil user", func(t *testing.T) {
		assert.ErrorContains(t, r.saveError(ctx, nil, testResource, testErr), "user is nil")
	})
	t.Run("success", func(t *testing.T) {
		assert.NoError(t, r.saveError(ctx, u, testResource, testErr))
	})
}

func TestRepository_lookupError(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)

	r, err := NewRepository(ctx, s, &sync.Map{},
		mapBasedAuthTokenKeyringLookup(map[ringToken]*authtokens.AuthToken{}),
		sliceBasedAuthTokenBoundaryReader(nil))
	require.NoError(t, err)

	testResource := targetResourceType
	testErr := fmt.Errorf("test error for %q", testResource)

	u := &user{
		Id:      "u1",
		Address: "addr",
	}
	require.NoError(t, r.rw.Create(ctx, u))

	t.Run("empty resource type", func(t *testing.T) {
		got, err := r.lookupError(ctx, u, "unknown")
		assert.ErrorContains(t, err, "resource type is invalid")
		assert.Nil(t, got)
	})
	t.Run("nil user", func(t *testing.T) {
		got, err := r.lookupError(ctx, nil, testResource)
		assert.ErrorContains(t, err, "user is nil")
		assert.Nil(t, got)
	})
	t.Run("empty user id", func(t *testing.T) {
		got, err := r.lookupError(ctx, &user{Address: "address"}, testResource)
		assert.ErrorContains(t, err, "user id is empty")
		assert.Nil(t, got)
	})
	t.Run("not found", func(t *testing.T) {
		got, err := r.lookupError(ctx, u, sessionResourceType)
		assert.NoError(t, err)
		assert.Nil(t, got)
	})
	t.Run("found", func(t *testing.T) {
		require.NoError(t, r.saveError(ctx, u, sessionResourceType, testErr))
		got, err := r.lookupError(ctx, u, sessionResourceType)
		assert.NoError(t, err)
		assert.NotNil(t, got)
	})
}
