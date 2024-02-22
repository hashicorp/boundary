// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/clientcache/internal/db"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
)

// testStaticResourceRetrievalFunc returns a function that always returns the
// provided slice and a nil error. The returned function can be passed into the
// options that provide a resource retrieval func such as
// WithTargetRetrievalFunc and WithSessionRetrievalFunc.  The provided refresh
// token determines the returned value and is a string representation of an
// incrementing integer. This integer is the index into the provided return
// values and once it reaches the length of the provided slice it returns an
// empty slice and the same refresh token repeatedly.
func testStaticResourceRetrievalFunc[T any](t *testing.T, ret [][]T, removed [][]string) func(context.Context, string, string, RefreshTokenValue) ([]T, []string, RefreshTokenValue, error) {
	t.Helper()
	require.Equal(t, len(ret), len(removed), "returned slice and removed slice must be the same length")
	return func(ctx context.Context, s1, s2 string, refToken RefreshTokenValue) ([]T, []string, RefreshTokenValue, error) {
		index := 0
		if refToken != "" {
			var err error
			index, err = strconv.Atoi(string(refToken))
			require.NoError(t, err)
		}

		switch {
		case len(ret) == 0:
			return nil, nil, "", nil
		case index > 0 && index >= len(ret):
			return []T{}, []string{}, RefreshTokenValue(fmt.Sprintf("%d", index)), nil
		default:
			return ret[index], removed[index], RefreshTokenValue(fmt.Sprintf("%d", index+1)), nil
		}
	}
}

// testNoRefreshRetrievalFunc simulates a controller that doesn't support refresh
// since it does not return any refresh token.
func testNoRefreshRetrievalFunc[T any](t *testing.T) func(context.Context, string, string, RefreshTokenValue) ([]T, []string, RefreshTokenValue, error) {
	return func(_ context.Context, _, _ string, _ RefreshTokenValue) ([]T, []string, RefreshTokenValue, error) {
		return nil, nil, "", ErrRefreshNotSupported
	}
}

// testErroringForRefreshTokenRetrievalFunc returns a refresh token error when
// the refresh token is not empty.  This is useful for testing behavior when
// the refresh token has expired or is otherwise invalid.
func testErroringForRefreshTokenRetrievalFunc[T any](t *testing.T, ret []T) func(context.Context, string, string, RefreshTokenValue) ([]T, []string, RefreshTokenValue, error) {
	return func(ctx context.Context, s1, s2 string, refToken RefreshTokenValue) ([]T, []string, RefreshTokenValue, error) {
		if refToken != "" {
			return nil, nil, "", api.ErrInvalidListToken
		}
		return ret, nil, "1", nil
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
	notFoundAuthTokens := []*authtokens.AuthToken{}
	randomErrorAuthTokens := []*authtokens.AuthToken{}
	fakeBoundaryLookupFn := func(ctx context.Context, addr, at string) (*authtokens.AuthToken, error) {
		for _, v := range randomErrorAuthTokens {
			if at == v.Token {
				return nil, errors.New("test error")
			}
		}
		for _, v := range notFoundAuthTokens {
			if at == v.Token {
				return nil, api.ErrNotFound
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
	rs, err := NewRefreshService(ctx, r, hclog.NewNullLogger(), 0, 0)
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

	t.Run("boundary in memory auth token not found", func(t *testing.T) {
		require.NoError(t, r.AddRawToken(ctx, boundaryAddr, at1a.Token))
		require.NoError(t, r.AddRawToken(ctx, boundaryAddr, at1b.Token))

		got, err := rs.cleanAndPickAuthTokens(ctx, u1)
		assert.NoError(t, err)
		assert.ElementsMatch(t, maps.Values(got), []string{at1a.Token, at1b.Token})

		t.Cleanup(func() {
			notFoundAuthTokens = nil
		})

		notFoundAuthTokens = []*authtokens.AuthToken{at1b}
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

func TestRefreshForSearch(t *testing.T) {
	ctx := context.Background()

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

	atMap[ringToken{"k", "t"}] = at

	t.Run("targets refreshed for searching", func(t *testing.T) {
		s, err := db.Open(ctx)
		require.NoError(t, err)
		r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(boundaryAuthTokens))
		require.NoError(t, err)
		rs, err := NewRefreshService(ctx, r, hclog.NewNullLogger(), time.Millisecond, 0)
		require.NoError(t, err)
		require.NoError(t, r.AddKeyringToken(ctx, boundaryAddr, KeyringToken{KeyringType: "k", TokenName: "t", AuthTokenId: at.Id}))

		retTargets := []*targets.Target{
			target("1"),
			target("2"),
			target("3"),
			target("4"),
		}
		opts := []Option{
			WithSessionRetrievalFunc(testStaticResourceRetrievalFunc[*sessions.Session](t, nil, nil)),
			WithTargetRetrievalFunc(testStaticResourceRetrievalFunc[*targets.Target](t,
				[][]*targets.Target{
					retTargets[:3],
					retTargets[3:],
				},
				[][]string{
					nil,
					{retTargets[0].Id, retTargets[1].Id},
				},
			)),
		}
		assert.NoError(t, rs.RefreshForSearch(ctx, at.Id, Targets, opts...))

		cachedTargets, err := r.ListTargets(ctx, at.Id)
		assert.NoError(t, err)
		assert.Empty(t, cachedTargets)

		// Now load up a few resources and a token, and trying again should
		// see the RefreshForSearch update more fields.
		assert.NoError(t, rs.Refresh(ctx, opts...))
		cachedTargets, err = r.ListTargets(ctx, at.Id)
		assert.NoError(t, err)
		assert.ElementsMatch(t, retTargets[:3], cachedTargets)

		// Let 2 milliseconds pass so the items are stale enough
		time.Sleep(2 * time.Millisecond)

		assert.NoError(t, rs.RefreshForSearch(ctx, at.Id, Targets, opts...))
		cachedTargets, err = r.ListTargets(ctx, at.Id)
		assert.NoError(t, err)
		assert.ElementsMatch(t, retTargets[2:], cachedTargets)
	})

	t.Run("targets forced refreshed for searching", func(t *testing.T) {
		s, err := db.Open(ctx)
		require.NoError(t, err)
		r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(boundaryAuthTokens))
		require.NoError(t, err)
		// Everything can stay stale for an hour
		rs, err := NewRefreshService(ctx, r, hclog.NewNullLogger(), time.Hour, 0)
		require.NoError(t, err)
		require.NoError(t, r.AddKeyringToken(ctx, boundaryAddr, KeyringToken{KeyringType: "k", TokenName: "t", AuthTokenId: at.Id}))

		retTargets := []*targets.Target{
			target("1"),
			target("2"),
			target("3"),
			target("4"),
		}
		opts := []Option{
			WithSessionRetrievalFunc(testStaticResourceRetrievalFunc[*sessions.Session](t, nil, nil)),
			WithTargetRetrievalFunc(testStaticResourceRetrievalFunc[*targets.Target](t,
				[][]*targets.Target{
					retTargets[:3],
					retTargets[3:],
				},
				[][]string{
					nil,
					{retTargets[0].Id, retTargets[1].Id},
				},
			)),
		}
		assert.NoError(t, rs.RefreshForSearch(ctx, at.Id, Targets, opts...))

		cachedTargets, err := r.ListTargets(ctx, at.Id)
		assert.NoError(t, err)
		assert.Empty(t, cachedTargets)

		// Now load up a few resources and a token, and trying again should
		// see the RefreshForSearch update more fields.
		assert.NoError(t, rs.Refresh(ctx, opts...))
		cachedTargets, err = r.ListTargets(ctx, at.Id)
		assert.NoError(t, err)
		assert.ElementsMatch(t, retTargets[:3], cachedTargets)

		// No refresh happened because it is not considered stale
		assert.NoError(t, rs.RefreshForSearch(ctx, at.Id, Targets, opts...))
		cachedTargets, err = r.ListTargets(ctx, at.Id)
		assert.NoError(t, err)
		assert.ElementsMatch(t, retTargets[:3], cachedTargets)

		// Now force refresh
		assert.NoError(t, rs.RefreshForSearch(ctx, at.Id, Targets, append(opts, WithIgnoreSearchStaleness(true))...))
		cachedTargets, err = r.ListTargets(ctx, at.Id)
		assert.NoError(t, err)
		assert.ElementsMatch(t, retTargets[2:], cachedTargets)
	})

	t.Run("no refresh token no refresh for search", func(t *testing.T) {
		s, err := db.Open(ctx)
		require.NoError(t, err)
		r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(boundaryAuthTokens))
		require.NoError(t, err)
		rs, err := NewRefreshService(ctx, r, hclog.NewNullLogger(), 0, 0)
		require.NoError(t, err)
		require.NoError(t, r.AddKeyringToken(ctx, boundaryAddr, KeyringToken{KeyringType: "k", TokenName: "t", AuthTokenId: at.Id}))

		retTargets := []*targets.Target{
			target("1"),
			target("2"),
		}

		// Get the first set of resources, but no refresh tokens
		err = rs.Refresh(ctx,
			WithSessionRetrievalFunc(testNoRefreshRetrievalFunc[*sessions.Session](t)),
			WithTargetRetrievalFunc(testNoRefreshRetrievalFunc[*targets.Target](t)))
		assert.ErrorContains(t, err, ErrRefreshNotSupported.Error())

		got, err := r.ListTargets(ctx, at.Id)
		assert.NoError(t, err)
		assert.Empty(t, got)

		// Now that we know that this user doesn't support refresh tokens, they
		// wont be refreshed any more, and we wont see the error when refreshing
		// any more.
		err = rs.Refresh(ctx,
			WithSessionRetrievalFunc(testNoRefreshRetrievalFunc[*sessions.Session](t)),
			WithTargetRetrievalFunc(testNoRefreshRetrievalFunc[*targets.Target](t)))
		assert.Nil(t, err)

		err = rs.RecheckCachingSupport(ctx,
			WithSessionRetrievalFunc(testNoRefreshRetrievalFunc[*sessions.Session](t)),
			WithTargetRetrievalFunc(testNoRefreshRetrievalFunc[*targets.Target](t)))
		assert.Nil(t, err)

		got, err = r.ListTargets(ctx, at.Id)
		assert.NoError(t, err)
		assert.Empty(t, got)

		// Now simulate the controller updating to support refresh tokens and
		// the resources starting to be cached.
		err = rs.RecheckCachingSupport(ctx,
			WithSessionRetrievalFunc(testStaticResourceRetrievalFunc[*sessions.Session](t, nil, nil)),
			WithTargetRetrievalFunc(testStaticResourceRetrievalFunc[*targets.Target](t, [][]*targets.Target{retTargets}, [][]string{{}})))
		assert.Nil(t, err, err)

		got, err = r.ListTargets(ctx, at.Id)
		assert.NoError(t, err)
		assert.Len(t, got, 2)
	})

	t.Run("sessions refreshed for searching", func(t *testing.T) {
		s, err := db.Open(ctx)
		require.NoError(t, err)
		r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(boundaryAuthTokens))
		require.NoError(t, err)
		rs, err := NewRefreshService(ctx, r, hclog.NewNullLogger(), 0, 0)
		require.NoError(t, err)
		require.NoError(t, r.AddKeyringToken(ctx, boundaryAddr, KeyringToken{KeyringType: "k", TokenName: "t", AuthTokenId: at.Id}))

		retSess := []*sessions.Session{
			session("1"),
			session("2"),
			session("3"),
			session("4"),
		}
		opts := []Option{
			WithTargetRetrievalFunc(testStaticResourceRetrievalFunc[*targets.Target](t, nil, nil)),
			WithSessionRetrievalFunc(testStaticResourceRetrievalFunc[*sessions.Session](t,
				[][]*sessions.Session{
					retSess[:3],
					retSess[3:],
				},
				[][]string{
					nil,
					{retSess[0].Id, retSess[1].Id},
				},
			)),
		}

		// First call doesn't sync anything because no sessions were already synced yet
		assert.NoError(t, rs.RefreshForSearch(ctx, at.Id, Sessions, opts...))
		cachedSessions, err := r.ListSessions(ctx, at.Id)
		assert.NoError(t, err)
		assert.Empty(t, cachedSessions)

		assert.NoError(t, rs.Refresh(ctx, opts...))
		cachedSessions, err = r.ListSessions(ctx, at.Id)
		assert.NoError(t, err)
		assert.ElementsMatch(t, retSess[:3], cachedSessions)

		// Second call removes the first 2 resources from the cache and adds the last
		assert.NoError(t, rs.RefreshForSearch(ctx, at.Id, Sessions, opts...))
		cachedSessions, err = r.ListSessions(ctx, at.Id)
		assert.NoError(t, err)
		assert.ElementsMatch(t, retSess[2:], cachedSessions)
	})

	t.Run("sessions forced refreshed for searching", func(t *testing.T) {
		s, err := db.Open(ctx)
		require.NoError(t, err)
		r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(boundaryAuthTokens))
		require.NoError(t, err)
		// Everything stays fresh for 1 hour
		rs, err := NewRefreshService(ctx, r, hclog.NewNullLogger(), time.Hour, 0)
		require.NoError(t, err)
		require.NoError(t, r.AddKeyringToken(ctx, boundaryAddr, KeyringToken{KeyringType: "k", TokenName: "t", AuthTokenId: at.Id}))

		retSess := []*sessions.Session{
			session("1"),
			session("2"),
			session("3"),
			session("4"),
		}
		opts := []Option{
			WithTargetRetrievalFunc(testStaticResourceRetrievalFunc[*targets.Target](t, nil, nil)),
			WithSessionRetrievalFunc(testStaticResourceRetrievalFunc[*sessions.Session](t,
				[][]*sessions.Session{
					retSess[:3],
					retSess[3:],
				},
				[][]string{
					nil,
					{retSess[0].Id, retSess[1].Id},
				},
			)),
		}

		// First call doesn't sync anything because no sessions were already synced yet
		assert.NoError(t, rs.RefreshForSearch(ctx, at.Id, Sessions, opts...))
		cachedSessions, err := r.ListSessions(ctx, at.Id)
		assert.NoError(t, err)
		assert.Empty(t, cachedSessions)

		assert.NoError(t, rs.Refresh(ctx, opts...))
		cachedSessions, err = r.ListSessions(ctx, at.Id)
		assert.NoError(t, err)
		assert.ElementsMatch(t, retSess[:3], cachedSessions)

		// Refresh for search doesn't refresh anything because it isn't stale
		assert.NoError(t, rs.RefreshForSearch(ctx, at.Id, Sessions, opts...))
		cachedSessions, err = r.ListSessions(ctx, at.Id)
		assert.NoError(t, err)
		assert.ElementsMatch(t, retSess[:3], cachedSessions)

		// Now force the refresh and see things get updated
		assert.NoError(t, rs.RefreshForSearch(ctx, at.Id, Sessions, append(opts, WithIgnoreSearchStaleness(true))...))
		cachedSessions, err = r.ListSessions(ctx, at.Id)
		assert.NoError(t, err)
		assert.ElementsMatch(t, retSess[2:], cachedSessions)
	})
}

func TestRefresh(t *testing.T) {
	ctx := context.Background()

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

	atMap[ringToken{"k", "t"}] = at

	t.Run("set targets", func(t *testing.T) {
		s, err := db.Open(ctx)
		require.NoError(t, err)
		r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(boundaryAuthTokens))
		require.NoError(t, err)
		rs, err := NewRefreshService(ctx, r, hclog.NewNullLogger(), 0, 0)
		require.NoError(t, err)
		require.NoError(t, r.AddKeyringToken(ctx, boundaryAddr, KeyringToken{KeyringType: "k", TokenName: "t", AuthTokenId: at.Id}))

		retTargets := []*targets.Target{
			target("1"),
			target("2"),
			target("3"),
			target("4"),
		}
		opts := []Option{
			WithSessionRetrievalFunc(testStaticResourceRetrievalFunc[*sessions.Session](t, nil, nil)),
			WithTargetRetrievalFunc(testStaticResourceRetrievalFunc[*targets.Target](t,
				[][]*targets.Target{
					retTargets[:3],
					retTargets[3:],
				},
				[][]string{
					nil,
					{retTargets[0].Id, retTargets[1].Id},
				},
			)),
		}
		assert.NoError(t, rs.Refresh(ctx, opts...))

		cachedTargets, err := r.ListTargets(ctx, at.Id)
		assert.NoError(t, err)
		assert.ElementsMatch(t, retTargets[:3], cachedTargets)

		// Second call removes the first 2 resources from the cache and adds the last
		assert.NoError(t, rs.Refresh(ctx, opts...))
		cachedTargets, err = r.ListTargets(ctx, at.Id)
		assert.NoError(t, err)
		assert.ElementsMatch(t, retTargets[2:], cachedTargets)
	})

	t.Run("set sessions", func(t *testing.T) {
		s, err := db.Open(ctx)
		require.NoError(t, err)
		r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(boundaryAuthTokens))
		require.NoError(t, err)
		rs, err := NewRefreshService(ctx, r, hclog.NewNullLogger(), 0, 0)
		require.NoError(t, err)
		require.NoError(t, r.AddKeyringToken(ctx, boundaryAddr, KeyringToken{KeyringType: "k", TokenName: "t", AuthTokenId: at.Id}))

		retSess := []*sessions.Session{
			session("1"),
			session("2"),
			session("3"),
			session("4"),
		}
		opts := []Option{
			WithTargetRetrievalFunc(testStaticResourceRetrievalFunc[*targets.Target](t, nil, nil)),
			WithSessionRetrievalFunc(testStaticResourceRetrievalFunc[*sessions.Session](t,
				[][]*sessions.Session{
					retSess[:3],
					retSess[3:],
				},
				[][]string{
					nil,
					{retSess[0].Id, retSess[1].Id},
				},
			)),
		}
		assert.NoError(t, rs.Refresh(ctx, opts...))
		cachedSessions, err := r.ListSessions(ctx, at.Id)
		assert.NoError(t, err)
		assert.ElementsMatch(t, retSess[:3], cachedSessions)

		// Second call removes the first 2 resources from the cache and adds the last
		assert.NoError(t, rs.Refresh(ctx, opts...))
		cachedSessions, err = r.ListSessions(ctx, at.Id)
		assert.NoError(t, err)
		assert.ElementsMatch(t, retSess[2:], cachedSessions)
	})

	t.Run("error propogates up", func(t *testing.T) {
		s, err := db.Open(ctx)
		require.NoError(t, err)
		r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(boundaryAuthTokens))
		require.NoError(t, err)
		rs, err := NewRefreshService(ctx, r, hclog.NewNullLogger(), 0, 0)
		require.NoError(t, err)
		require.NoError(t, r.AddKeyringToken(ctx, boundaryAddr, KeyringToken{KeyringType: "k", TokenName: "t", AuthTokenId: at.Id}))

		innerErr := errors.New("test error")
		err = rs.Refresh(ctx,
			WithSessionRetrievalFunc(testStaticResourceRetrievalFunc[*sessions.Session](t, nil, nil)),
			WithTargetRetrievalFunc(func(ctx context.Context, addr, token string, refreshTok RefreshTokenValue) ([]*targets.Target, []string, RefreshTokenValue, error) {
				require.Equal(t, boundaryAddr, addr)
				require.Equal(t, at.Token, token)
				return nil, nil, "", innerErr
			}))
		assert.ErrorContains(t, err, innerErr.Error())
		err = rs.Refresh(ctx,
			WithTargetRetrievalFunc(testStaticResourceRetrievalFunc[*targets.Target](t, nil, nil)),
			WithSessionRetrievalFunc(func(ctx context.Context, addr, token string, refreshTok RefreshTokenValue) ([]*sessions.Session, []string, RefreshTokenValue, error) {
				require.Equal(t, boundaryAddr, addr)
				require.Equal(t, at.Token, token)
				return nil, nil, "", innerErr
			}))
		assert.ErrorContains(t, err, innerErr.Error())
	})

	t.Run("tokens that are no longer in the ring is deleted", func(t *testing.T) {
		s, err := db.Open(ctx)
		require.NoError(t, err)
		r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(boundaryAuthTokens))
		require.NoError(t, err)
		rs, err := NewRefreshService(ctx, r, hclog.NewNullLogger(), 0, 0)
		require.NoError(t, err)
		require.NoError(t, r.AddKeyringToken(ctx, boundaryAddr, KeyringToken{KeyringType: "k", TokenName: "t", AuthTokenId: at.Id}))

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
			WithSessionRetrievalFunc(testStaticResourceRetrievalFunc[*sessions.Session](t, nil, nil)),
			WithTargetRetrievalFunc(testStaticResourceRetrievalFunc[*targets.Target](t, nil, nil)))

		ps, err = r.listTokens(ctx, u)
		require.NoError(t, err)
		assert.Empty(t, ps)

		// And since the last token was deleted, the user also was deleted
		us, err = r.listUsers(ctx)
		require.NoError(t, err)
		assert.Empty(t, us)
	})
}

func TestRecheckCachingSupport(t *testing.T) {
	ctx := context.Background()

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

	atMap[ringToken{"k", "t"}] = at

	t.Run("targets", func(t *testing.T) {
		s, err := db.Open(ctx)
		require.NoError(t, err)
		r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(boundaryAuthTokens))
		require.NoError(t, err)
		rs, err := NewRefreshService(ctx, r, hclog.NewNullLogger(), 0, 0)
		require.NoError(t, err)
		require.NoError(t, r.AddKeyringToken(ctx, boundaryAddr, KeyringToken{KeyringType: "k", TokenName: "t", AuthTokenId: at.Id}))

		// Since this user doesn't have any resources, the user's data will still
		// only get updated with a call to Refresh.
		assert.NoError(t, rs.RecheckCachingSupport(ctx,
			WithSessionRetrievalFunc(testNoRefreshRetrievalFunc[*sessions.Session](t)),
			WithTargetRetrievalFunc(testNoRefreshRetrievalFunc[*targets.Target](t))))

		got, err := r.ListTargets(ctx, at.Id)
		assert.NoError(t, err)
		assert.Empty(t, got)

		err = rs.Refresh(ctx,
			WithSessionRetrievalFunc(testNoRefreshRetrievalFunc[*sessions.Session](t)),
			WithTargetRetrievalFunc(testNoRefreshRetrievalFunc[*targets.Target](t)))
		assert.ErrorIs(t, err, ErrRefreshNotSupported)

		got, err = r.ListTargets(ctx, at.Id)
		assert.NoError(t, err)
		assert.Empty(t, got)

		// now a full fetch will work since the user has resources and no refresh token
		assert.NoError(t, rs.RecheckCachingSupport(ctx,
			WithSessionRetrievalFunc(testNoRefreshRetrievalFunc[*sessions.Session](t)),
			WithTargetRetrievalFunc(testNoRefreshRetrievalFunc[*targets.Target](t))))
	})

	t.Run("sessions", func(t *testing.T) {
		s, err := db.Open(ctx)
		require.NoError(t, err)
		r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(boundaryAuthTokens))
		require.NoError(t, err)
		rs, err := NewRefreshService(ctx, r, hclog.NewNullLogger(), 0, 0)
		require.NoError(t, err)
		require.NoError(t, r.AddKeyringToken(ctx, boundaryAddr, KeyringToken{KeyringType: "k", TokenName: "t", AuthTokenId: at.Id}))

		assert.NoError(t, rs.RecheckCachingSupport(ctx,
			WithTargetRetrievalFunc(testNoRefreshRetrievalFunc[*targets.Target](t)),
			WithSessionRetrievalFunc(testNoRefreshRetrievalFunc[*sessions.Session](t))))

		got, err := r.ListSessions(ctx, at.Id)
		assert.NoError(t, err)
		assert.Empty(t, got)

		err = rs.Refresh(ctx,
			WithTargetRetrievalFunc(testNoRefreshRetrievalFunc[*targets.Target](t)),
			WithSessionRetrievalFunc(testNoRefreshRetrievalFunc[*sessions.Session](t)))
		assert.ErrorIs(t, err, ErrRefreshNotSupported)

		got, err = r.ListSessions(ctx, at.Id)
		assert.NoError(t, err)
		assert.Empty(t, got)

		assert.NoError(t, rs.RecheckCachingSupport(ctx,
			WithTargetRetrievalFunc(testNoRefreshRetrievalFunc[*targets.Target](t)),
			WithSessionRetrievalFunc(testNoRefreshRetrievalFunc[*sessions.Session](t))))
		got, err = r.ListSessions(ctx, at.Id)
		assert.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("error propogates up", func(t *testing.T) {
		s, err := db.Open(ctx)
		require.NoError(t, err)
		r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(boundaryAuthTokens))
		require.NoError(t, err)
		rs, err := NewRefreshService(ctx, r, hclog.NewNullLogger(), 0, 0)
		require.NoError(t, err)
		require.NoError(t, r.AddKeyringToken(ctx, boundaryAddr, KeyringToken{KeyringType: "k", TokenName: "t", AuthTokenId: at.Id}))

		err = rs.Refresh(ctx,
			WithTargetRetrievalFunc(testNoRefreshRetrievalFunc[*targets.Target](t)),
			WithSessionRetrievalFunc(testNoRefreshRetrievalFunc[*sessions.Session](t)))
		assert.ErrorIs(t, err, ErrRefreshNotSupported)

		innerErr := errors.New("test error")
		err = rs.RecheckCachingSupport(ctx,
			WithSessionRetrievalFunc(testNoRefreshRetrievalFunc[*sessions.Session](t)),
			WithTargetRetrievalFunc(func(ctx context.Context, addr, token string, refreshTok RefreshTokenValue) ([]*targets.Target, []string, RefreshTokenValue, error) {
				require.Equal(t, boundaryAddr, addr)
				require.Equal(t, at.Token, token)
				return nil, nil, "", innerErr
			}))
		assert.ErrorContains(t, err, innerErr.Error())

		err = rs.RecheckCachingSupport(ctx,
			WithSessionRetrievalFunc(testNoRefreshRetrievalFunc[*sessions.Session](t)),
			WithTargetRetrievalFunc(func(ctx context.Context, addr, token string, refreshTok RefreshTokenValue) ([]*targets.Target, []string, RefreshTokenValue, error) {
				require.Equal(t, boundaryAddr, addr)
				require.Equal(t, at.Token, token)
				return nil, nil, "", innerErr
			}))
		assert.ErrorContains(t, err, innerErr.Error())
	})

	t.Run("tokens that are no longer in the ring is deleted", func(t *testing.T) {
		s, err := db.Open(ctx)
		require.NoError(t, err)
		r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(boundaryAuthTokens))
		require.NoError(t, err)
		rs, err := NewRefreshService(ctx, r, hclog.NewNullLogger(), 0, 0)
		require.NoError(t, err)
		require.NoError(t, r.AddKeyringToken(ctx, boundaryAddr, KeyringToken{KeyringType: "k", TokenName: "t", AuthTokenId: at.Id}))

		err = rs.Refresh(ctx,
			WithTargetRetrievalFunc(testNoRefreshRetrievalFunc[*targets.Target](t)),
			WithSessionRetrievalFunc(testNoRefreshRetrievalFunc[*sessions.Session](t)))
		assert.ErrorIs(t, err, ErrRefreshNotSupported)

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

		err = rs.RecheckCachingSupport(ctx,
			WithSessionRetrievalFunc(testNoRefreshRetrievalFunc[*sessions.Session](t)),
			WithTargetRetrievalFunc(testNoRefreshRetrievalFunc[*targets.Target](t)))
		assert.NoError(t, err)

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
		Id:                fmt.Sprintf("target_%s", suffix),
		Name:              fmt.Sprintf("name_%s", suffix),
		Description:       fmt.Sprintf("description_%s", suffix),
		Address:           fmt.Sprintf("address_%s", suffix),
		ScopeId:           fmt.Sprintf("p_%s", suffix),
		Type:              "tcp",
		SessionMaxSeconds: 1234,
	}
}

func session(suffix string) *sessions.Session {
	return &sessions.Session{
		Id:   fmt.Sprintf("session_%s", suffix),
		Type: "tcp",
	}
}
