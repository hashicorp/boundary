// Copyright (c) HashiCorp, Inc.
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
	return func(k, t string) *authtokens.AuthToken {
		return m[ringToken{k, t}]
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

func TestRepository_SaveError(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)

	r, err := NewRepository(ctx, s, &sync.Map{},
		mapBasedAuthTokenKeyringLookup(map[ringToken]*authtokens.AuthToken{}),
		sliceBasedAuthTokenBoundaryReader(nil))
	require.NoError(t, err)

	testResource := "test_resource_type"
	testErr := fmt.Errorf("test error for %q", testResource)

	u := &user{
		Id:      "u1",
		Address: "addr",
	}
	require.NoError(t, r.rw.Create(ctx, u))

	t.Run("empty resource type", func(t *testing.T) {
		assert.ErrorContains(t, r.SaveError(ctx, u, "", testErr), "resource type is empty")
	})
	t.Run("nil error", func(t *testing.T) {
		assert.ErrorContains(t, r.SaveError(ctx, u, testResource, nil), "error is nil")
	})
	t.Run("nil user", func(t *testing.T) {
		assert.ErrorContains(t, r.SaveError(ctx, nil, testResource, testErr), "user is nil")
	})
	t.Run("success", func(t *testing.T) {
		assert.NoError(t, r.SaveError(ctx, u, testResource, testErr))
	})
}
