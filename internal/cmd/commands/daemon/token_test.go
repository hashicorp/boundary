// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
	stdErrors "errors"
	"net/http"
	"sync"
	"testing"

	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/daemon/cache"
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
func mapBasedAuthTokenKeyringLookup(m map[ringToken]*authtokens.AuthToken) cache.KeyringTokenLookupFn {
	return func(k, t string) *authtokens.AuthToken {
		return m[ringToken{k, t}]
	}
}

// sliceBasedAuthTokenBoundaryReader provides a fake BoundaryTokenReaderFn that uses
// the provided map to lookup an auth tokens information.
func sliceBasedAuthTokenBoundaryReader(s []*authtokens.AuthToken) cache.BoundaryTokenReaderFn {
	return func(ctx context.Context, addr, at string) (*authtokens.AuthToken, error) {
		for _, v := range s {
			if at == v.Token {
				return v, nil
			}
		}
		return nil, stdErrors.New("not found")
	}
}

type testRefresher struct {
	called bool
}

func (r *testRefresher) refresh() {
	r.called = true
}

func TestKeyringToken(t *testing.T) {
	ctx := context.Background()
	s, _, err := openStore(ctx, "", false)
	require.NoError(t, err)

	at := &authtokens.AuthToken{
		Id:     "at_1",
		Token:  "at_1_token",
		UserId: "user",
	}
	boundaryAuthTokens := []*authtokens.AuthToken{at}
	keyring := "k"
	tokenName := "t"
	atMap := map[ringToken]*authtokens.AuthToken{
		{keyring, tokenName}: at,
	}
	r, err := cache.NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(boundaryAuthTokens))
	require.NoError(t, err)

	tr := &testRefresher{}
	ph, err := newTokenHandlerFunc(ctx, r, tr)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/tokens", ph)

	tmpdir := t.TempDir()
	l, err := listener(ctx, tmpdir)
	require.NoError(t, err)
	srv := &http.Server{
		Handler: mux,
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		assert.ErrorIs(t, srv.Serve(l), http.ErrServerClosed)
	}()

	t.Run("missing keyring", func(t *testing.T) {
		pa := &upsertTokenRequest{
			Keyring: &keyringToken{
				KeyringType: "",
				TokenName:   tokenName,
			},
			BoundaryAddr: "http://127.0.0.1",
			AuthTokenId:  at.Id,
		}
		apiErr, err := addToken(ctx, tmpdir, pa)
		assert.NoError(t, err)
		require.NotNil(t, apiErr)
		assert.Contains(t, apiErr.Message, "KeyringType is a required field but was empty")
		assert.False(t, tr.called)
	})

	t.Run("none keyring", func(t *testing.T) {
		pa := &upsertTokenRequest{
			Keyring: &keyringToken{
				KeyringType: base.NoneKeyring,
				TokenName:   tokenName,
			},
			BoundaryAddr: "http://127.0.0.1",
			AuthTokenId:  at.Id,
		}
		apiErr, err := addToken(ctx, tmpdir, pa)
		assert.NoError(t, err)
		require.NotNil(t, apiErr)
		assert.Contains(t, apiErr.Message, "KeyringType is set to none which is not supported")
		assert.False(t, tr.called)
	})

	t.Run("missing token name", func(t *testing.T) {
		pa := &upsertTokenRequest{
			Keyring: &keyringToken{
				KeyringType: keyring,
				TokenName:   "",
			},
			BoundaryAddr: "http://127.0.0.1",
			AuthTokenId:  at.Id,
		}
		apiErr, err := addToken(ctx, tmpdir, pa)
		assert.NoError(t, err)
		assert.NotNil(t, apiErr)
		assert.Contains(t, apiErr.Message, "TokenName is a required field but was empty")
		assert.False(t, tr.called)
	})

	t.Run("missing boundary address", func(t *testing.T) {
		pa := &upsertTokenRequest{
			Keyring: &keyringToken{
				KeyringType: keyring,
				TokenName:   tokenName,
			},
			BoundaryAddr: "",
			AuthTokenId:  at.Id,
		}
		apiErr, err := addToken(ctx, tmpdir, pa)
		assert.NoError(t, err)
		assert.NotNil(t, apiErr)
		assert.Contains(t, apiErr.Message, "BoundaryAddr is a required field but was empty")
		assert.False(t, tr.called)
	})

	t.Run("missing auth token id", func(t *testing.T) {
		pa := &upsertTokenRequest{
			Keyring: &keyringToken{
				KeyringType: keyring,
				TokenName:   tokenName,
			},
			BoundaryAddr: "http://127.0.0.1",
			AuthTokenId:  "",
		}
		apiErr, err := addToken(ctx, tmpdir, pa)
		assert.NoError(t, err)
		assert.NotNil(t, apiErr)
		assert.Contains(t, apiErr.Message, "AuthTokenId is a required field but was empty")
		assert.False(t, tr.called)
	})

	t.Run("mismatched auth token id", func(t *testing.T) {
		pa := &upsertTokenRequest{
			Keyring: &keyringToken{
				KeyringType: keyring,
				TokenName:   tokenName,
			},
			BoundaryAddr: "http://127.0.0.1",
			AuthTokenId:  "at_doesntmatch",
		}
		apiErr, err := addToken(ctx, tmpdir, pa)
		assert.NoError(t, err)
		assert.NotNil(t, apiErr)
		assert.Contains(t, apiErr.Message, "Failed to add a keyring stored token")
		assert.False(t, tr.called)
	})

	t.Run("success", func(t *testing.T) {
		pa := &upsertTokenRequest{
			Keyring: &keyringToken{
				KeyringType: keyring,
				TokenName:   tokenName,
			},
			BoundaryAddr: "http://127.0.0.1",
			AuthTokenId:  at.Id,
		}
		apiErr, err := addToken(ctx, tmpdir, pa)
		assert.NoError(t, err)
		assert.Nil(t, apiErr)
		assert.True(t, tr.called)

		p, err := r.LookupToken(ctx, pa.AuthTokenId)
		require.NoError(t, err)
		assert.NotNil(t, p)
		assert.Equal(t, at.Id, p.Id)
	})
	srv.Shutdown(ctx)
	wg.Wait()
}

func TestKeyringlessToken(t *testing.T) {
	ctx := context.Background()
	s, _, err := openStore(ctx, "", false)
	require.NoError(t, err)

	at := &authtokens.AuthToken{
		Id:     "at_1",
		Token:  "at_1_token",
		UserId: "user",
	}
	boundaryAuthTokens := []*authtokens.AuthToken{at}
	atMap := map[ringToken]*authtokens.AuthToken{}
	r, err := cache.NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(boundaryAuthTokens))
	require.NoError(t, err)

	tr := &testRefresher{}
	ph, err := newTokenHandlerFunc(ctx, r, tr)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/tokens", ph)

	tmpdir := t.TempDir()
	l, err := listener(ctx, tmpdir)
	require.NoError(t, err)
	srv := &http.Server{
		Handler: mux,
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		assert.ErrorIs(t, srv.Serve(l), http.ErrServerClosed)
	}()

	t.Run("missing boundary address", func(t *testing.T) {
		pa := &upsertTokenRequest{
			BoundaryAddr: "",
			AuthTokenId:  at.Id,
			AuthToken:    at.Token,
		}
		apiErr, err := addToken(ctx, tmpdir, pa)
		assert.NoError(t, err)
		assert.NotNil(t, apiErr)
		assert.Contains(t, apiErr.Message, "BoundaryAddr is a required field but was empty")
		assert.False(t, tr.called)
	})

	t.Run("missing auth token id", func(t *testing.T) {
		pa := &upsertTokenRequest{
			BoundaryAddr: "http://127.0.0.1",
			AuthTokenId:  "",
			AuthToken:    at.Token,
		}
		apiErr, err := addToken(ctx, tmpdir, pa)
		assert.NoError(t, err)
		assert.NotNil(t, apiErr)
		assert.Contains(t, apiErr.Message, "AuthTokenId is a required field but was empty")
		assert.False(t, tr.called)
	})

	t.Run("mismatched auth token id", func(t *testing.T) {
		pa := &upsertTokenRequest{
			BoundaryAddr: "http://127.0.0.1",
			AuthTokenId:  "at_doesntmatch",
			AuthToken:    at.Token,
		}
		apiErr, err := addToken(ctx, tmpdir, pa)
		assert.NoError(t, err)
		assert.NotNil(t, apiErr)
		assert.Contains(t, apiErr.Message, "The auth token id doesn't match the auth token's prefix")
		assert.False(t, tr.called)
	})

	t.Run("success", func(t *testing.T) {
		pa := &upsertTokenRequest{
			BoundaryAddr: "http://127.0.0.1",
			AuthTokenId:  at.Id,
			AuthToken:    at.Token,
		}
		apiErr, err := addToken(ctx, tmpdir, pa)
		assert.NoError(t, err)
		assert.Nil(t, apiErr)
		assert.True(t, tr.called)

		p, err := r.LookupToken(ctx, pa.AuthTokenId)
		require.NoError(t, err)
		assert.NotNil(t, p)
		assert.Equal(t, at.Id, p.Id)
	})
	srv.Shutdown(ctx)
	wg.Wait()
}
