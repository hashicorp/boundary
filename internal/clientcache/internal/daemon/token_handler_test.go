// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/internal/clientcache/internal/cache"
	cachedb "github.com/hashicorp/boundary/internal/clientcache/internal/db"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/go-hclog"
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
	return func(k, t string) (*authtokens.AuthToken, error) {
		return m[ringToken{k, t}], nil
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
		return nil, errors.New("not found")
	}
}

type testRefresher struct {
	called bool
}

func (r *testRefresher) refresh() {
	r.called = true
}

func addToken(t *testing.T, h http.Handler, tokReq *UpsertTokenRequest) *api.Error {
	t.Helper()
	b, err := json.Marshal(tokReq)
	require.NoError(t, err)
	rawBody := bytes.NewBuffer(b)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/tokens", rawBody)
	h.ServeHTTP(rec, req)
	if rec.Result().StatusCode == http.StatusNoContent {
		return nil
	}
	apiErr := &api.Error{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), apiErr))
	return apiErr
}

func TestKeyringToken(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
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
	ph, err := newTokenHandlerFunc(ctx, r, tr, hclog.NewNullLogger())
	require.NoError(t, err)

	t.Run("missing keyring", func(t *testing.T) {
		pa := &UpsertTokenRequest{
			Keyring: &KeyringToken{
				KeyringType: "",
				TokenName:   tokenName,
			},
			BoundaryAddr: "http://127.0.0.1",
			AuthTokenId:  at.Id,
		}
		apiErr := addToken(t, ph, pa)
		require.NotNil(t, apiErr)
		assert.Contains(t, apiErr.Message, "keyring_type is a required field but was empty")
		assert.False(t, tr.called)
	})

	t.Run("none keyring", func(t *testing.T) {
		pa := &UpsertTokenRequest{
			Keyring: &KeyringToken{
				KeyringType: base.NoneKeyring,
				TokenName:   tokenName,
			},
			BoundaryAddr: "http://127.0.0.1",
			AuthTokenId:  at.Id,
		}
		apiErr := addToken(t, ph, pa)
		require.NotNil(t, apiErr)
		assert.Contains(t, apiErr.Message, "keyring.keyring_type is set to none which is not supported")
		assert.False(t, tr.called)
	})

	t.Run("missing token name", func(t *testing.T) {
		pa := &UpsertTokenRequest{
			Keyring: &KeyringToken{
				KeyringType: keyring,
				TokenName:   "",
			},
			BoundaryAddr: "http://127.0.0.1",
			AuthTokenId:  at.Id,
		}
		apiErr := addToken(t, ph, pa)
		assert.NotNil(t, apiErr)
		assert.Contains(t, apiErr.Message, "keyring.token_name is a required field but was empty")
		assert.False(t, tr.called)
	})

	t.Run("missing boundary address", func(t *testing.T) {
		pa := &UpsertTokenRequest{
			Keyring: &KeyringToken{
				KeyringType: keyring,
				TokenName:   tokenName,
			},
			BoundaryAddr: "",
			AuthTokenId:  at.Id,
		}
		apiErr := addToken(t, ph, pa)
		assert.NotNil(t, apiErr)
		assert.Contains(t, apiErr.Message, "boundary_addr is a required field but was empty")
		assert.False(t, tr.called)
	})

	t.Run("missing auth token id", func(t *testing.T) {
		pa := &UpsertTokenRequest{
			Keyring: &KeyringToken{
				KeyringType: keyring,
				TokenName:   tokenName,
			},
			BoundaryAddr: "http://127.0.0.1",
			AuthTokenId:  "",
		}
		apiErr := addToken(t, ph, pa)
		assert.NotNil(t, apiErr)
		assert.Contains(t, apiErr.Message, "auth_token_id is a required field but was empty")
		assert.False(t, tr.called)
	})

	t.Run("mismatched auth token id", func(t *testing.T) {
		pa := &UpsertTokenRequest{
			Keyring: &KeyringToken{
				KeyringType: keyring,
				TokenName:   tokenName,
			},
			BoundaryAddr: "http://127.0.0.1",
			AuthTokenId:  "at_doesntmatch",
		}
		apiErr := addToken(t, ph, pa)
		assert.NotNil(t, apiErr)
		assert.Contains(t, apiErr.Message, "Failed to add a keyring stored token")
		assert.False(t, tr.called)
	})

	t.Run("success", func(t *testing.T) {
		pa := &UpsertTokenRequest{
			Keyring: &KeyringToken{
				KeyringType: keyring,
				TokenName:   tokenName,
			},
			BoundaryAddr: "http://127.0.0.1",
			AuthTokenId:  at.Id,
		}
		apiErr := addToken(t, ph, pa)
		assert.Nil(t, apiErr)
		assert.True(t, tr.called)

		p, err := r.LookupToken(ctx, pa.AuthTokenId)
		require.NoError(t, err)
		assert.NotNil(t, p)
		assert.Equal(t, at.Id, p.Id)
	})
}

func TestKeyringlessToken(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
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
	ph, err := newTokenHandlerFunc(ctx, r, tr, hclog.NewNullLogger())
	require.NoError(t, err)

	t.Run("missing boundary address", func(t *testing.T) {
		pa := &UpsertTokenRequest{
			BoundaryAddr: "",
			AuthTokenId:  at.Id,
			AuthToken:    at.Token,
		}
		apiErr := addToken(t, ph, pa)
		assert.NotNil(t, apiErr)
		assert.Contains(t, apiErr.Message, "boundary_addr is a required field but was empty")
		assert.False(t, tr.called)
	})

	t.Run("missing auth token id", func(t *testing.T) {
		pa := &UpsertTokenRequest{
			BoundaryAddr: "http://127.0.0.1",
			AuthTokenId:  "",
			AuthToken:    at.Token,
		}
		apiErr := addToken(t, ph, pa)
		assert.NotNil(t, apiErr)
		assert.Contains(t, apiErr.Message, "auth_token_id is a required field but was empty")
		assert.False(t, tr.called)
	})

	t.Run("mismatched auth token id", func(t *testing.T) {
		pa := &UpsertTokenRequest{
			BoundaryAddr: "http://127.0.0.1",
			AuthTokenId:  "at_doesntmatch",
			AuthToken:    at.Token,
		}
		apiErr := addToken(t, ph, pa)
		assert.NotNil(t, apiErr)
		assert.Contains(t, apiErr.Message, "auth_token_id doesn't match the auth_token's prefix")
		assert.False(t, tr.called)
	})

	t.Run("success", func(t *testing.T) {
		pa := &UpsertTokenRequest{
			BoundaryAddr: "http://127.0.0.1",
			AuthTokenId:  at.Id,
			AuthToken:    at.Token,
		}
		apiErr := addToken(t, ph, pa)
		assert.Nil(t, apiErr)
		assert.True(t, tr.called)

		p, err := r.LookupToken(ctx, pa.AuthTokenId)
		require.NoError(t, err)
		assert.NotNil(t, p)
		assert.Equal(t, at.Id, p.Id)
	})
}

func TestUpsertTokenRequest_String(t *testing.T) {
	cases := []struct {
		name string
		req  *UpsertTokenRequest
		want string
	}{
		{
			name: "auth token fully redacted",
			req: &UpsertTokenRequest{
				BoundaryAddr: "test",
				AuthToken:    "at_wrong_SomethingElseHere",
				AuthTokenId:  "at_prefix",
			},
			want: "BoundaryAddr: \"test\", AuthTokenId: \"at_prefix\", AuthToken: \"/*redacted*/\"",
		},
		{
			name: "auth token partially redacted",
			req: &UpsertTokenRequest{
				BoundaryAddr: "test",
				AuthToken:    "at_prefix_SomethingElseHere",
				AuthTokenId:  "at_prefix",
			},
			want: "BoundaryAddr: \"test\", AuthTokenId: \"at_prefix\", AuthToken: \"at_prefix_/*redacted*/\"",
		},
		{
			name: "auth token partially redacted",
			req: &UpsertTokenRequest{
				BoundaryAddr: "test",
				Keyring: &KeyringToken{
					TokenName:   "token",
					KeyringType: "type",
				},
				AuthToken:   "at_prefix_SomethingElseHere",
				AuthTokenId: "at_prefix",
			},
			want: "BoundaryAddr: \"test\", AuthTokenId: \"at_prefix\", Keyring: {KeyringType:type TokenName:token}, AuthToken: \"at_prefix_/*redacted*/\"",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.req.String())
		})
	}
}
