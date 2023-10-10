// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/clientcache/internal/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
)

// testStaticResourceRetrievalFunc returns a function that always returns the
// provided slice and a nil error. The returned function can be passed into the
// options that provide a resource retrieval func such as
// WithTargetRetrievalFunc and WithSessionRetrievalFunc.
func testStaticResourceRetrievalFunc[T any](ret []T) func(context.Context, string, string) ([]T, error) {
	return func(ctx context.Context, s1, s2 string) ([]T, error) {
		return ret, nil
	}
}

func TestCleanAndPickTokens(t *testing.T) {
	ctx := context.Background()
	s, err := db.Open(ctx)
	require.NoError(t, err)

	boundaryAddr := "address"
	u1 := &user{Id: "u1", Address: boundaryAddr}
	at1a := &authtokens.AuthToken{
		Id:             "at_1a",
		Token:          "at_1a_token",
		UserId:         u1.Id,
		ExpirationTime: time.Now().Add(time.Minute),
	}
	at1b := &authtokens.AuthToken{
		Id:             "at_1b",
		Token:          "at_1b_token",
		UserId:         u1.Id,
		ExpirationTime: time.Now().Add(time.Minute),
	}

	keyringOnlyUser := &user{Id: "keyringUser", Address: boundaryAddr}
	keyringAuthToken1 := &authtokens.AuthToken{
		Id:             "at_2a",
		Token:          "at_2a_token",
		UserId:         keyringOnlyUser.Id,
		ExpirationTime: time.Now().Add(time.Minute),
	}
	keyringAuthToken2 := &authtokens.AuthToken{
		Id:             "at_2b",
		Token:          "at_2b_token",
		UserId:         keyringOnlyUser.Id,
		ExpirationTime: time.Now().Add(time.Minute),
	}

	boundaryAuthTokens := []*authtokens.AuthToken{at1a, keyringAuthToken1, at1b, keyringAuthToken2}
	unauthorizedAuthTokens := []*authtokens.AuthToken{}
	randomErrorAuthTokens := []*authtokens.AuthToken{}
	fakeBoundaryLookupFn := func(ctx context.Context, addr, at string) (*authtokens.AuthToken, error) {
		for _, v := range randomErrorAuthTokens {
			if at == v.Token {
				return nil, errors.New("test error")
			}
		}
		for _, v := range unauthorizedAuthTokens {
			if at == v.Token {
				return nil, api.ErrUnauthorized
			}
		}
		for _, v := range boundaryAuthTokens {
			if at == v.Token {
				return v, nil
			}
		}
		return nil, errors.New("not found")
	}

	atMap := make(map[ringToken]*authtokens.AuthToken)
	r, err := NewRepository(ctx, s, &sync.Map{},
		mapBasedAuthTokenKeyringLookup(atMap),
		fakeBoundaryLookupFn)
	require.NoError(t, err)
	rs, err := NewRefreshService(ctx, r)
	require.NoError(t, err)

	t.Run("unknown user", func(t *testing.T) {
		got, err := rs.cleanAndPickAuthTokens(ctx, &user{Id: "unknownuser", Address: "unknown"})
		assert.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("both memory and keyring stored token", func(t *testing.T) {
		key := ringToken{"k1", "t1"}
		atMap[key] = at1a
		require.NoError(t, r.AddKeyringToken(ctx, boundaryAddr, KeyringToken{
			KeyringType: key.k,
			TokenName:   key.t,
			AuthTokenId: at1a.Id,
		}))
		require.NoError(t, r.AddRawToken(ctx, boundaryAddr, at1b.Token))

		got, err := rs.cleanAndPickAuthTokens(ctx, u1)
		assert.NoError(t, err)
		assert.ElementsMatch(t, maps.Values(got), []string{at1a.Token, at1b.Token})

		// delete the keyringToken from the keyring and see it get removed from the response
		delete(atMap, key)
		got, err = rs.cleanAndPickAuthTokens(ctx, u1)
		assert.NoError(t, err)
		assert.ElementsMatch(t, maps.Values(got), []string{at1b.Token})
	})

	t.Run("2 memory tokens", func(t *testing.T) {
		require.NoError(t, r.AddRawToken(ctx, boundaryAddr, at1a.Token))
		require.NoError(t, r.AddRawToken(ctx, boundaryAddr, at1b.Token))

		got, err := rs.cleanAndPickAuthTokens(ctx, u1)
		assert.NoError(t, err)
		assert.ElementsMatch(t, maps.Values(got), []string{at1a.Token, at1b.Token})
	})

	t.Run("boundary in memory auth token expires", func(t *testing.T) {
		require.NoError(t, r.AddRawToken(ctx, boundaryAddr, at1a.Token))
		require.NoError(t, r.AddRawToken(ctx, boundaryAddr, at1b.Token))

		got, err := rs.cleanAndPickAuthTokens(ctx, u1)
		assert.NoError(t, err)
		assert.ElementsMatch(t, maps.Values(got), []string{at1a.Token, at1b.Token})

		t.Cleanup(func() {
			unauthorizedAuthTokens = nil
		})

		unauthorizedAuthTokens = []*authtokens.AuthToken{at1b}
		got, err = rs.cleanAndPickAuthTokens(ctx, u1)
		assert.NoError(t, err)
		assert.ElementsMatch(t, maps.Values(got), []string{at1a.Token})
	})

	t.Run("boundary keyring auths token expires", func(t *testing.T) {
		key1 := ringToken{"k1", "t1"}
		atMap[key1] = keyringAuthToken1
		require.NoError(t, r.AddKeyringToken(ctx, boundaryAddr, KeyringToken{
			KeyringType: key1.k,
			TokenName:   key1.t,
			AuthTokenId: keyringAuthToken1.Id,
		}))
		key2 := ringToken{"k2", "t2"}
		atMap[key2] = keyringAuthToken2
		require.NoError(t, r.AddKeyringToken(ctx, boundaryAddr, KeyringToken{
			KeyringType: key2.k,
			TokenName:   key2.t,
			AuthTokenId: keyringAuthToken2.Id,
		}))

		got, err := rs.cleanAndPickAuthTokens(ctx, keyringOnlyUser)
		assert.NoError(t, err)
		assert.ElementsMatch(t, maps.Values(got), []string{keyringAuthToken1.Token, keyringAuthToken2.Token})

		t.Cleanup(func() {
			unauthorizedAuthTokens = nil
		})

		unauthorizedAuthTokens = []*authtokens.AuthToken{keyringAuthToken2}
		got, err = rs.cleanAndPickAuthTokens(ctx, keyringOnlyUser)
		assert.NoError(t, err)
		assert.ElementsMatch(t, maps.Values(got), []string{keyringAuthToken1.Token})
	})

	t.Run("boundary in memory auth token check errors", func(t *testing.T) {
		require.NoError(t, r.AddRawToken(ctx, boundaryAddr, at1a.Token))
		require.NoError(t, r.AddRawToken(ctx, boundaryAddr, at1b.Token))

		got, err := rs.cleanAndPickAuthTokens(ctx, u1)
		assert.NoError(t, err)
		assert.ElementsMatch(t, maps.Values(got), []string{at1a.Token, at1b.Token})

		t.Cleanup(func() {
			randomErrorAuthTokens = nil
		})

		randomErrorAuthTokens = []*authtokens.AuthToken{at1b}
		got, err = rs.cleanAndPickAuthTokens(ctx, u1)
		assert.NoError(t, err)
		assert.ElementsMatch(t, maps.Values(got), []string{at1a.Token})
	})

	t.Run("boundary keyring auths token check errors", func(t *testing.T) {
		key1 := ringToken{"k1", "t1"}
		atMap[key1] = keyringAuthToken1
		require.NoError(t, r.AddKeyringToken(ctx, boundaryAddr, KeyringToken{
			KeyringType: key1.k,
			TokenName:   key1.t,
			AuthTokenId: keyringAuthToken1.Id,
		}))
		key2 := ringToken{"k2", "t2"}
		atMap[key2] = keyringAuthToken2
		require.NoError(t, r.AddKeyringToken(ctx, boundaryAddr, KeyringToken{
			KeyringType: key2.k,
			TokenName:   key2.t,
			AuthTokenId: keyringAuthToken2.Id,
		}))

		got, err := rs.cleanAndPickAuthTokens(ctx, keyringOnlyUser)
		assert.NoError(t, err)
		assert.ElementsMatch(t, maps.Values(got), []string{keyringAuthToken1.Token, keyringAuthToken2.Token})

		t.Cleanup(func() {
			randomErrorAuthTokens = nil
		})

		randomErrorAuthTokens = []*authtokens.AuthToken{keyringAuthToken2}
		got, err = rs.cleanAndPickAuthTokens(ctx, keyringOnlyUser)
		assert.NoError(t, err)
		assert.ElementsMatch(t, maps.Values(got), []string{keyringAuthToken1.Token})
	})

	t.Run("2 keyring tokens", func(t *testing.T) {
		key1 := ringToken{"k1", "t1"}
		atMap[key1] = keyringAuthToken1
		require.NoError(t, r.AddKeyringToken(ctx, boundaryAddr, KeyringToken{
			KeyringType: key1.k,
			TokenName:   key1.t,
			AuthTokenId: keyringAuthToken1.Id,
		}))
		key2 := ringToken{"k2", "t2"}
		atMap[key2] = keyringAuthToken2
		require.NoError(t, r.AddKeyringToken(ctx, boundaryAddr, KeyringToken{
			KeyringType: key2.k,
			TokenName:   key2.t,
			AuthTokenId: keyringAuthToken2.Id,
		}))

		got, err := rs.cleanAndPickAuthTokens(ctx, keyringOnlyUser)
		assert.NoError(t, err)
		assert.ElementsMatch(t, maps.Values(got), []string{keyringAuthToken1.Token, keyringAuthToken2.Token})

		// Removing all keyring references and then cleaning auth tokens
		// removes all auth tokens, along with the user
		gotU, err := r.listUsers(ctx)
		assert.NoError(t, err)
		assert.Contains(t, gotU, keyringOnlyUser)

		delete(atMap, key1)
		delete(atMap, key2)
		got, err = rs.cleanAndPickAuthTokens(ctx, keyringOnlyUser)
		assert.NoError(t, err)
		assert.Empty(t, got)

		gotT, err := r.listTokens(ctx, keyringOnlyUser)
		assert.NoError(t, err)
		assert.Empty(t, gotT)
		gotU, err = r.listUsers(ctx)
		assert.NoError(t, err)
		assert.NotContains(t, gotU, keyringOnlyUser)
	})
}

func TestRefresh(t *testing.T) {
	ctx := context.Background()
	s, err := db.Open(ctx)
	require.NoError(t, err)

	boundaryAddr := "address"
	u := &user{Id: "u1", Address: boundaryAddr}
	at := &authtokens.AuthToken{
		Id:             "at_1",
		Token:          "at_1_token",
		UserId:         u.Id,
		ExpirationTime: time.Now().Add(time.Minute),
	}

	boundaryAuthTokens := []*authtokens.AuthToken{at}
	atMap := make(map[ringToken]*authtokens.AuthToken)
	r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(boundaryAuthTokens))
	require.NoError(t, err)
	rs, err := NewRefreshService(ctx, r)
	require.NoError(t, err)

	atMap[ringToken{"k", "t"}] = at
	require.NoError(t, r.AddKeyringToken(ctx, boundaryAddr, KeyringToken{KeyringType: "k", TokenName: "t", AuthTokenId: at.Id}))

	t.Run("set targets", func(t *testing.T) {
		retTargets := []*targets.Target{
			target("1"),
			target("2"),
			target("3"),
		}
		assert.NoError(t, rs.Refresh(ctx,
			WithSessionRetrievalFunc(testStaticResourceRetrievalFunc[*sessions.Session](nil)),
			WithTargetRetrievalFunc(func(ctx context.Context, addr, token string) ([]*targets.Target, error) {
				require.Equal(t, boundaryAddr, addr)
				require.Equal(t, at.Token, token)
				return retTargets, nil
			})))

		cachedTargets, err := r.ListTargets(ctx, at.Id)
		assert.NoError(t, err)
		assert.ElementsMatch(t, retTargets, cachedTargets)

		t.Run("empty response clears it out", func(t *testing.T) {
			assert.NoError(t, rs.Refresh(ctx,
				WithSessionRetrievalFunc(testStaticResourceRetrievalFunc[*sessions.Session](nil)),
				WithTargetRetrievalFunc(func(ctx context.Context, addr, token string) ([]*targets.Target, error) {
					require.Equal(t, boundaryAddr, addr)
					require.Equal(t, at.Token, token)
					return nil, nil
				})))

			cachedTargets, err := r.ListTargets(ctx, at.Id)
			assert.NoError(t, err)
			assert.Empty(t, cachedTargets)
		})
	})

	t.Run("set sessions", func(t *testing.T) {
		retSess := []*sessions.Session{
			session("1"),
			session("2"),
			session("3"),
		}
		assert.NoError(t, rs.Refresh(ctx,
			WithTargetRetrievalFunc(testStaticResourceRetrievalFunc[*targets.Target](nil)),
			WithSessionRetrievalFunc(testStaticResourceRetrievalFunc(retSess))))

		cachedSessions, err := r.ListSessions(ctx, at.Id)
		assert.NoError(t, err)
		assert.ElementsMatch(t, retSess, cachedSessions)

		t.Run("empty response clears it out", func(t *testing.T) {
			assert.NoError(t, rs.Refresh(ctx,
				WithTargetRetrievalFunc(testStaticResourceRetrievalFunc[*targets.Target](nil)),
				WithSessionRetrievalFunc(testStaticResourceRetrievalFunc[*sessions.Session](nil))))

			cachedTargets, err := r.ListSessions(ctx, at.Id)
			assert.NoError(t, err)
			assert.Empty(t, cachedTargets)
		})
	})

	t.Run("error propogates up", func(t *testing.T) {
		innerErr := errors.New("test error")
		err := rs.Refresh(ctx,
			WithSessionRetrievalFunc(testStaticResourceRetrievalFunc[*sessions.Session](nil)),
			WithTargetRetrievalFunc(func(ctx context.Context, addr, token string) ([]*targets.Target, error) {
				require.Equal(t, boundaryAddr, addr)
				require.Equal(t, at.Token, token)
				return nil, innerErr
			}))
		assert.ErrorContains(t, err, innerErr.Error())
		err = rs.Refresh(ctx,
			WithTargetRetrievalFunc(testStaticResourceRetrievalFunc[*targets.Target](nil)),
			WithSessionRetrievalFunc(func(ctx context.Context, addr, token string) ([]*sessions.Session, error) {
				require.Equal(t, boundaryAddr, addr)
				require.Equal(t, at.Token, token)
				return nil, innerErr
			}))
		assert.ErrorContains(t, err, innerErr.Error())
	})

	t.Run("tokens that are no longer in the ring is deleted", func(t *testing.T) {
		// Remove the token from the keyring, see that we can still see the
		// token and then user until a Refresh happens which causes them to be
		// cleaned up.
		delete(atMap, ringToken{"k", "t"})

		ps, err := r.listTokens(ctx, u)
		require.NoError(t, err)
		assert.Len(t, ps, 1)

		us, err := r.listUsers(ctx)
		require.NoError(t, err)
		assert.Len(t, us, 1)

		rs.Refresh(ctx,
			WithSessionRetrievalFunc(testStaticResourceRetrievalFunc[*sessions.Session](nil)),
			WithTargetRetrievalFunc(testStaticResourceRetrievalFunc[*targets.Target](nil)))

		ps, err = r.listTokens(ctx, u)
		require.NoError(t, err)
		assert.Empty(t, ps)

		// And since the last token was deleted, the user also was deleted
		us, err = r.listUsers(ctx)
		require.NoError(t, err)
		assert.Empty(t, us)
	})
}

func target(suffix string) *targets.Target {
	return &targets.Target{
		Id:          fmt.Sprintf("target_%s", suffix),
		Name:        fmt.Sprintf("name_%s", suffix),
		Description: fmt.Sprintf("description_%s", suffix),
		Address:     fmt.Sprintf("address_%s", suffix),
		Type:        "tcp",
	}
}

func session(suffix string) *sessions.Session {
	return &sessions.Session{
		Id:   fmt.Sprintf("session_%s", suffix),
		Type: "tcp",
	}
}
