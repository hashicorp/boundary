// Copyright IBM Corp. 2020, 2025
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
	"github.com/hashicorp/boundary/api/aliases"
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

func testTargetStaticResourceRetrievalFunc(inFunc func(ctx context.Context, s1, s2 string, refToken RefreshTokenValue) ([]*targets.Target, []string, RefreshTokenValue, error)) TargetRetrievalFunc {
	return func(ctx context.Context, addr, authTok string, refreshTok RefreshTokenValue, inPage *targets.TargetListResult, opt ...Option) (ret *targets.TargetListResult, refreshToken RefreshTokenValue, err error) {
		retTargets, removed, refreshToken, err := inFunc(ctx, addr, authTok, refreshTok)
		if err != nil {
			return nil, "", err
		}

		ret = &targets.TargetListResult{
			Items:        retTargets,
			RemovedIds:   removed,
			ResponseType: "complete",
		}
		return ret, refreshToken, nil
	}
}

func testSessionStaticResourceRetrievalFunc(inFunc func(ctx context.Context, s1, s2 string, refToken RefreshTokenValue) ([]*sessions.Session, []string, RefreshTokenValue, error)) SessionRetrievalFunc {
	return func(ctx context.Context, addr, authTok string, refreshTok RefreshTokenValue, inPage *sessions.SessionListResult, opt ...Option) (ret *sessions.SessionListResult, refreshToken RefreshTokenValue, err error) {
		retSessions, removed, refreshToken, err := inFunc(ctx, addr, authTok, refreshTok)
		if err != nil {
			return nil, "", err
		}

		ret = &sessions.SessionListResult{
			Items:        retSessions,
			RemovedIds:   removed,
			ResponseType: "complete",
		}
		return ret, refreshToken, nil
	}
}

func testResolvableAliasStaticResourceRetrievalFunc(inFunc func(ctx context.Context, s1, s2, s3 string, refToken RefreshTokenValue) ([]*aliases.Alias, []string, RefreshTokenValue, error)) ResolvableAliasRetrievalFunc {
	return func(ctx context.Context, addr, authTok, userId string, refreshTok RefreshTokenValue, inPage *aliases.AliasListResult, opt ...Option) (ret *aliases.AliasListResult, refreshToken RefreshTokenValue, err error) {
		retSessions, removed, refreshToken, err := inFunc(ctx, addr, authTok, userId, refreshTok)
		if err != nil {
			return nil, "", err
		}

		ret = &aliases.AliasListResult{
			Items:        retSessions,
			RemovedIds:   removed,
			ResponseType: "complete",
		}
		return ret, refreshToken, nil
	}
}

// testNoRefreshRetrievalFunc simulates a controller that doesn't support refresh
// since it does not return any refresh token.
func testNoRefreshRetrievalFunc[T any](_ *testing.T) func(context.Context, string, string, RefreshTokenValue) ([]T, []string, RefreshTokenValue, error) {
	return func(_ context.Context, _, _ string, _ RefreshTokenValue) ([]T, []string, RefreshTokenValue, error) {
		return nil, nil, "", ErrRefreshNotSupported
	}
}

// testErroringForRefreshTokenRetrievalFunc returns a refresh token error when
// the refresh token is not empty.  This is useful for testing behavior when
// the refresh token has expired or is otherwise invalid.
func testErroringForRefreshTokenRetrievalFunc[T any](_ *testing.T, ret []T) func(context.Context, string, string, RefreshTokenValue) ([]T, []string, RefreshTokenValue, error) {
	return func(ctx context.Context, s1, s2 string, refToken RefreshTokenValue) ([]T, []string, RefreshTokenValue, error) {
		if refToken != "" {
			return nil, nil, "", api.ErrInvalidListToken
		}
		return ret, nil, "1", nil
	}
}

// testStaticResourceRetrievalFunc returns a function that always returns the
// provided slice and a nil error. The returned function can be passed into the
// options that provide a resource retrieval func such as
// WithTargetRetrievalFunc and WithSessionRetrievalFunc.  The provided refresh
// token determines the returned value and is a string representation of an
// incrementing integer. This integer is the index into the provided return
// values and once it reaches the length of the provided slice it returns an
// empty slice and the same refresh token repeatedly. This is for retrieval
// functions that require an id be provided for listing purposes like when
// listing resolvable aliases.
func testStaticResourceRetrievalFuncForId[T any](t *testing.T, ret [][]T, removed [][]string) func(context.Context, string, string, string, RefreshTokenValue) ([]T, []string, RefreshTokenValue, error) {
	t.Helper()
	require.Equal(t, len(ret), len(removed), "returned slice and removed slice must be the same length")
	return func(ctx context.Context, s1, s2, s3 string, refToken RefreshTokenValue) ([]T, []string, RefreshTokenValue, error) {
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
// since it does not return any refresh token. This is for retrieval
// functions that require an id be provided for listing purposes like when
// listing resolvable aliases.
func testNoRefreshRetrievalFuncForId[T any](_ *testing.T) func(context.Context, string, string, string, RefreshTokenValue) ([]T, []string, RefreshTokenValue, error) {
	return func(_ context.Context, _, _, _ string, _ RefreshTokenValue) ([]T, []string, RefreshTokenValue, error) {
		return nil, nil, "", ErrRefreshNotSupported
	}
}

// testErroringForRefreshTokenRetrievalFuncForId returns a refresh token error when
// the refresh token is not empty. This is useful for testing behavior when
// the refresh token has expired or is otherwise invalid. This is for retrieval
// functions that require an id be provided for listing purposes like when
// listing resolvable aliases.
func testErroringForRefreshTokenRetrievalFuncForId[T any](_ *testing.T, ret []T) func(context.Context, string, string, string, RefreshTokenValue) ([]T, []string, RefreshTokenValue, error) {
	return func(ctx context.Context, s1, s2, s3 string, refToken RefreshTokenValue) ([]T, []string, RefreshTokenValue, error) {
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
			WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testStaticResourceRetrievalFuncForId[*aliases.Alias](t, nil, nil))),
			WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc[*sessions.Session](t, nil, nil))),
			WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc[*targets.Target](t,
				[][]*targets.Target{
					retTargets[:3],
					retTargets[3:],
				},
				[][]string{
					nil,
					{retTargets[0].Id, retTargets[1].Id},
				},
			))),
		}
		assert.NoError(t, rs.RefreshForSearch(ctx, at.Id, Targets, opts...))

		cachedTargets, err := r.ListTargets(ctx, at.Id)
		require.NoError(t, err)
		assert.Empty(t, cachedTargets.Targets)
		assert.Empty(t, cachedTargets.ResolvableAliases)
		assert.Empty(t, cachedTargets.Sessions)
		assert.False(t, cachedTargets.Incomplete)

		// Now load up a few resources and a token, and trying again should
		// see the RefreshForSearch update more fields.
		assert.NoError(t, rs.Refresh(ctx, opts...))
		cachedTargets, err = r.ListTargets(ctx, at.Id)
		assert.NoError(t, err)
		assert.ElementsMatch(t, retTargets[:3], cachedTargets.Targets)

		// Let 2 milliseconds pass so the items are stale enough
		time.Sleep(2 * time.Millisecond)

		assert.NoError(t, rs.RefreshForSearch(ctx, at.Id, Targets, opts...))
		cachedTargets, err = r.ListTargets(ctx, at.Id)
		assert.NoError(t, err)
		assert.ElementsMatch(t, retTargets[2:], cachedTargets.Targets)
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
			WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testStaticResourceRetrievalFuncForId[*aliases.Alias](t, nil, nil))),
			WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc[*sessions.Session](t, nil, nil))),
			WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc[*targets.Target](t,
				[][]*targets.Target{
					retTargets[:3],
					retTargets[3:],
				},
				[][]string{
					nil,
					{retTargets[0].Id, retTargets[1].Id},
				},
			))),
		}
		assert.NoError(t, rs.RefreshForSearch(ctx, at.Id, Targets, opts...))

		cachedTargets, err := r.ListTargets(ctx, at.Id)
		require.NoError(t, err)
		assert.Empty(t, cachedTargets.Targets)
		assert.Empty(t, cachedTargets.ResolvableAliases)
		assert.Empty(t, cachedTargets.Sessions)
		assert.False(t, cachedTargets.Incomplete)

		// Now load up a few resources and a token, and trying again should
		// see the RefreshForSearch update more fields.
		assert.NoError(t, rs.Refresh(ctx, opts...))
		cachedTargets, err = r.ListTargets(ctx, at.Id)
		assert.NoError(t, err)
		assert.ElementsMatch(t, retTargets[:3], cachedTargets.Targets)

		// No refresh happened because it is not considered stale
		assert.NoError(t, rs.RefreshForSearch(ctx, at.Id, Targets, opts...))
		cachedTargets, err = r.ListTargets(ctx, at.Id)
		assert.NoError(t, err)
		assert.ElementsMatch(t, retTargets[:3], cachedTargets.Targets)

		// Now force refresh
		assert.NoError(t, rs.RefreshForSearch(ctx, at.Id, Targets, append(opts, WithIgnoreSearchStaleness(true))...))
		cachedTargets, err = r.ListTargets(ctx, at.Id)
		assert.NoError(t, err)
		assert.ElementsMatch(t, retTargets[2:], cachedTargets.Targets)
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
			WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testStaticResourceRetrievalFuncForId[*aliases.Alias](t, nil, nil))),
			WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testNoRefreshRetrievalFunc[*sessions.Session](t))),
			WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testNoRefreshRetrievalFunc[*targets.Target](t))))
		assert.ErrorContains(t, err, ErrRefreshNotSupported.Error())

		got, err := r.ListTargets(ctx, at.Id)
		require.NoError(t, err)
		assert.Empty(t, got.Targets)
		assert.Empty(t, got.ResolvableAliases)
		assert.Empty(t, got.Sessions)
		assert.False(t, got.Incomplete)

		// Now that we know that this user doesn't support refresh tokens, they
		// wont be refreshed any more, and we wont see the error when refreshing
		// any more.
		err = rs.Refresh(ctx,
			WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testNoRefreshRetrievalFuncForId[*aliases.Alias](t))),
			WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testNoRefreshRetrievalFunc[*targets.Target](t))),
			WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testNoRefreshRetrievalFunc[*sessions.Session](t))))
		assert.Nil(t, err)

		err = rs.RecheckCachingSupport(ctx,
			WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testNoRefreshRetrievalFuncForId[*aliases.Alias](t))),
			WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testNoRefreshRetrievalFunc[*targets.Target](t))),
			WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testNoRefreshRetrievalFunc[*sessions.Session](t))))
		assert.Nil(t, err)

		got, err = r.ListTargets(ctx, at.Id)
		require.NoError(t, err)
		assert.Empty(t, got.Targets)
		assert.Empty(t, got.ResolvableAliases)
		assert.Empty(t, got.Sessions)
		assert.False(t, got.Incomplete)

		// Now simulate the controller updating to support refresh tokens and
		// the resources starting to be cached.
		err = rs.RecheckCachingSupport(ctx,
			WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testStaticResourceRetrievalFuncForId[*aliases.Alias](t, nil, nil))),
			WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc[*targets.Target](t, [][]*targets.Target{retTargets}, [][]string{{}}))),
			WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc[*sessions.Session](t, nil, nil))),
		)
		assert.Nil(t, err, err)

		got, err = r.ListTargets(ctx, at.Id)
		assert.NoError(t, err)
		assert.Len(t, got.Targets, 2)
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
			WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testStaticResourceRetrievalFuncForId[*aliases.Alias](t, nil, nil))),
			WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc[*targets.Target](t, nil, nil))),
			WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc[*sessions.Session](t,
				[][]*sessions.Session{
					retSess[:3],
					retSess[3:],
				},
				[][]string{
					nil,
					{retSess[0].Id, retSess[1].Id},
				},
			))),
		}

		// First call doesn't sync anything because no sessions were already synced yet
		assert.NoError(t, rs.RefreshForSearch(ctx, at.Id, Sessions, opts...))
		cachedSessions, err := r.ListSessions(ctx, at.Id)
		require.NoError(t, err)
		assert.Empty(t, cachedSessions.Targets)
		assert.Empty(t, cachedSessions.ResolvableAliases)
		assert.Empty(t, cachedSessions.Sessions)
		assert.False(t, cachedSessions.Incomplete)

		assert.NoError(t, rs.Refresh(ctx, opts...))
		cachedSessions, err = r.ListSessions(ctx, at.Id)
		assert.NoError(t, err)
		assert.ElementsMatch(t, retSess[:3], cachedSessions.Sessions)

		// Second call removes the first 2 resources from the cache and adds the last
		assert.NoError(t, rs.RefreshForSearch(ctx, at.Id, Sessions, opts...))
		cachedSessions, err = r.ListSessions(ctx, at.Id)
		assert.NoError(t, err)
		assert.ElementsMatch(t, retSess[2:], cachedSessions.Sessions)
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
			WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testStaticResourceRetrievalFuncForId[*aliases.Alias](t, nil, nil))),
			WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc[*targets.Target](t, nil, nil))),
			WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc[*sessions.Session](t,
				[][]*sessions.Session{
					retSess[:3],
					retSess[3:],
				},
				[][]string{
					nil,
					{retSess[0].Id, retSess[1].Id},
				},
			))),
		}

		// First call doesn't sync anything because no sessions were already synced yet
		assert.NoError(t, rs.RefreshForSearch(ctx, at.Id, Sessions, opts...))
		cachedSessions, err := r.ListSessions(ctx, at.Id)
		require.NoError(t, err)
		assert.Empty(t, cachedSessions.Targets)
		assert.Empty(t, cachedSessions.ResolvableAliases)
		assert.Empty(t, cachedSessions.Sessions)
		assert.False(t, cachedSessions.Incomplete)

		assert.NoError(t, rs.Refresh(ctx, opts...))
		cachedSessions, err = r.ListSessions(ctx, at.Id)
		assert.NoError(t, err)
		assert.ElementsMatch(t, retSess[:3], cachedSessions.Sessions)

		// Refresh for search doesn't refresh anything because it isn't stale
		assert.NoError(t, rs.RefreshForSearch(ctx, at.Id, Sessions, opts...))
		cachedSessions, err = r.ListSessions(ctx, at.Id)
		assert.NoError(t, err)
		assert.ElementsMatch(t, retSess[:3], cachedSessions.Sessions)

		// Now force the refresh and see things get updated
		assert.NoError(t, rs.RefreshForSearch(ctx, at.Id, Sessions, append(opts, WithIgnoreSearchStaleness(true))...))
		cachedSessions, err = r.ListSessions(ctx, at.Id)
		assert.NoError(t, err)
		assert.ElementsMatch(t, retSess[2:], cachedSessions.Sessions)
	})

	t.Run("aliases refreshed for searching", func(t *testing.T) {
		s, err := db.Open(ctx)
		require.NoError(t, err)
		r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(boundaryAuthTokens))
		require.NoError(t, err)
		rs, err := NewRefreshService(ctx, r, hclog.Default(), 0, 0)
		require.NoError(t, err)
		require.NoError(t, r.AddKeyringToken(ctx, boundaryAddr, KeyringToken{KeyringType: "k", TokenName: "t", AuthTokenId: at.Id}))

		retAl := []*aliases.Alias{
			alias("1"),
			alias("2"),
			alias("3"),
			alias("4"),
		}
		opts := []Option{
			WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc[*sessions.Session](t, nil, nil))),
			WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc[*targets.Target](t, nil, nil))),
			WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testStaticResourceRetrievalFuncForId[*aliases.Alias](t,
				[][]*aliases.Alias{
					retAl[:3],
					retAl[3:],
				},
				[][]string{
					nil,
					{retAl[0].Id, retAl[1].Id},
				},
			))),
		}

		// First call doesn't sync anything because no aliases were already synced yet
		assert.NoError(t, rs.RefreshForSearch(ctx, at.Id, ResolvableAliases, opts...))
		cachedAliases, err := r.ListResolvableAliases(ctx, at.Id)
		require.NoError(t, err)
		assert.Empty(t, cachedAliases.Targets)
		assert.Empty(t, cachedAliases.ResolvableAliases)
		assert.Empty(t, cachedAliases.Sessions)
		assert.False(t, cachedAliases.Incomplete)

		assert.NoError(t, rs.Refresh(ctx, opts...))
		cachedAliases, err = r.ListResolvableAliases(ctx, at.Id)
		require.NoError(t, err)
		assert.ElementsMatch(t, retAl[:3], cachedAliases.ResolvableAliases)

		// Second call removes the first 2 resources from the cache and adds the last
		assert.NoError(t, rs.RefreshForSearch(ctx, at.Id, ResolvableAliases, opts...))
		cachedAliases, err = r.ListResolvableAliases(ctx, at.Id)
		require.NoError(t, err)
		assert.ElementsMatch(t, retAl[2:], cachedAliases.ResolvableAliases)
	})

	t.Run("aliases forced refreshed for searching", func(t *testing.T) {
		s, err := db.Open(ctx)
		require.NoError(t, err)
		r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(boundaryAuthTokens))
		require.NoError(t, err)
		// Everything stays fresh for 1 hour
		rs, err := NewRefreshService(ctx, r, hclog.Default(), time.Hour, 0)
		require.NoError(t, err)
		require.NoError(t, r.AddKeyringToken(ctx, boundaryAddr, KeyringToken{KeyringType: "k", TokenName: "t", AuthTokenId: at.Id}))

		retAls := []*aliases.Alias{
			alias("1"),
			alias("2"),
			alias("3"),
			alias("4"),
		}
		opts := []Option{
			WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc[*sessions.Session](t, nil, nil))),
			WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc[*targets.Target](t, nil, nil))),
			WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testStaticResourceRetrievalFuncForId[*aliases.Alias](t,
				[][]*aliases.Alias{
					retAls[:3],
					retAls[3:],
				},
				[][]string{
					nil,
					{retAls[0].Id, retAls[1].Id},
				},
			))),
		}

		// First call doesn't sync anything because no aliases were already synced yet
		assert.NoError(t, rs.RefreshForSearch(ctx, at.Id, ResolvableAliases, opts...))
		cachedAliases, err := r.ListResolvableAliases(ctx, at.Id)
		require.NoError(t, err)
		assert.Empty(t, cachedAliases.Targets)
		assert.Empty(t, cachedAliases.ResolvableAliases)
		assert.Empty(t, cachedAliases.Sessions)
		assert.False(t, cachedAliases.Incomplete)

		assert.NoError(t, rs.Refresh(ctx, opts...))
		cachedAliases, err = r.ListResolvableAliases(ctx, at.Id)
		require.NoError(t, err)
		assert.ElementsMatch(t, retAls[:3], cachedAliases.ResolvableAliases)

		// Refresh for search doesn't refresh anything because it isn't stale
		assert.NoError(t, rs.RefreshForSearch(ctx, at.Id, ResolvableAliases, opts...))
		cachedAliases, err = r.ListResolvableAliases(ctx, at.Id)
		require.NoError(t, err)
		assert.ElementsMatch(t, retAls[:3], cachedAliases.ResolvableAliases)

		// Now force the refresh and see things get updated
		assert.NoError(t, rs.RefreshForSearch(ctx, at.Id, ResolvableAliases, append(opts, WithIgnoreSearchStaleness(true))...))
		cachedAliases, err = r.ListResolvableAliases(ctx, at.Id)
		require.NoError(t, err)
		assert.ElementsMatch(t, retAls[2:], cachedAliases.ResolvableAliases)
	})
}

func TestRefreshNonBlocking(t *testing.T) {
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
		t.Parallel()
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
			WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testStaticResourceRetrievalFuncForId[*aliases.Alias](t, nil, nil))),
			WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc[*sessions.Session](t, nil, nil))),
			WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc[*targets.Target](t,
				[][]*targets.Target{
					retTargets[:3],
					retTargets[3:],
				},
				[][]string{
					nil,
					{retTargets[0].Id, retTargets[1].Id},
				},
			))),
		}

		refreshWaitChs := &testRefreshWaitChs{
			firstSempahore:  make(chan struct{}),
			secondSemaphore: make(chan struct{}),
		}
		wg := new(sync.WaitGroup)
		wg.Add(2)
		extraOpts := []Option{WithTestRefreshWaitChs(refreshWaitChs), WithIgnoreSearchStaleness(true)}
		go func() {
			defer wg.Done()
			blockingRefreshError := rs.RefreshForSearch(ctx, at.Id, Targets, append(opts, extraOpts...)...)
			assert.NoError(t, blockingRefreshError)
		}()
		go func() {
			defer wg.Done()
			// Sleep here to ensure ordering of the calls since both goroutines
			// are spawned at the same time
			<-refreshWaitChs.firstSempahore
			nonblockingRefreshError := rs.RefreshForSearch(ctx, at.Id, Targets, append(opts, extraOpts...)...)
			close(refreshWaitChs.secondSemaphore)
			assert.ErrorIs(t, nonblockingRefreshError, ErrRefreshInProgress)
		}()
		wg.Wait()

		// Unlike in the TestRefreshForSearch test, since we did a force
		// refresh we do expect to see values
		cachedTargets, err := r.ListTargets(ctx, at.Id)
		assert.NoError(t, err)
		assert.ElementsMatch(t, retTargets[:3], cachedTargets.Targets)
	})

	t.Run("sessions refreshed for searching", func(t *testing.T) {
		t.Parallel()
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
			WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testStaticResourceRetrievalFuncForId[*aliases.Alias](t, nil, nil))),
			WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc[*targets.Target](t, nil, nil))),
			WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc[*sessions.Session](t,
				[][]*sessions.Session{
					retSess[:3],
					retSess[3:],
				},
				[][]string{
					nil,
					{retSess[0].Id, retSess[1].Id},
				},
			))),
		}

		refreshWaitChs := &testRefreshWaitChs{
			firstSempahore:  make(chan struct{}),
			secondSemaphore: make(chan struct{}),
		}
		wg := new(sync.WaitGroup)
		wg.Add(2)
		extraOpts := []Option{WithTestRefreshWaitChs(refreshWaitChs), WithIgnoreSearchStaleness(true)}
		go func() {
			defer wg.Done()
			blockingRefreshError := rs.RefreshForSearch(ctx, at.Id, Sessions, append(opts, extraOpts...)...)
			assert.NoError(t, blockingRefreshError)
		}()
		go func() {
			defer wg.Done()
			// Sleep here to ensure ordering of the calls since both goroutines
			// are spawned at the same time
			<-refreshWaitChs.firstSempahore
			nonblockingRefreshError := rs.RefreshForSearch(ctx, at.Id, Sessions, append(opts, extraOpts...)...)
			close(refreshWaitChs.secondSemaphore)
			assert.ErrorIs(t, nonblockingRefreshError, ErrRefreshInProgress)
		}()

		wg.Wait()

		// Unlike in the TestRefreshForSearch test, since we are did a force
		// refresh we do expect to see values
		cachedSessions, err := r.ListSessions(ctx, at.Id)
		assert.NoError(t, err)
		assert.ElementsMatch(t, retSess[:3], cachedSessions.Sessions)
	})

	t.Run("aliases refreshed for searching", func(t *testing.T) {
		t.Parallel()
		s, err := db.Open(ctx)
		require.NoError(t, err)
		r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(boundaryAuthTokens))
		require.NoError(t, err)
		rs, err := NewRefreshService(ctx, r, hclog.Default(), 0, 0)
		require.NoError(t, err)
		require.NoError(t, r.AddKeyringToken(ctx, boundaryAddr, KeyringToken{KeyringType: "k", TokenName: "t", AuthTokenId: at.Id}))

		retAl := []*aliases.Alias{
			alias("1"),
			alias("2"),
			alias("3"),
			alias("4"),
		}
		opts := []Option{
			WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc[*sessions.Session](t, nil, nil))),
			WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc[*targets.Target](t, nil, nil))),
			WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testStaticResourceRetrievalFuncForId[*aliases.Alias](t,
				[][]*aliases.Alias{
					retAl[:3],
					retAl[3:],
				},
				[][]string{
					nil,
					{retAl[0].Id, retAl[1].Id},
				},
			))),
		}

		refreshWaitChs := &testRefreshWaitChs{
			firstSempahore:  make(chan struct{}),
			secondSemaphore: make(chan struct{}),
		}
		wg := new(sync.WaitGroup)
		wg.Add(2)
		extraOpts := []Option{WithTestRefreshWaitChs(refreshWaitChs), WithIgnoreSearchStaleness(true)}
		go func() {
			defer wg.Done()
			blockingRefreshError := rs.RefreshForSearch(ctx, at.Id, ResolvableAliases, append(opts, extraOpts...)...)
			assert.NoError(t, blockingRefreshError)
		}()
		go func() {
			defer wg.Done()
			// Sleep here to ensure ordering of the calls since both goroutines
			// are spawned at the same time
			<-refreshWaitChs.firstSempahore
			nonblockingRefreshError := rs.RefreshForSearch(ctx, at.Id, ResolvableAliases, append(opts, extraOpts...)...)
			close(refreshWaitChs.secondSemaphore)
			assert.ErrorIs(t, nonblockingRefreshError, ErrRefreshInProgress)
		}()

		wg.Wait()

		// Unlike in the TestRefreshForSearch test, since we are did a force
		// refresh we do expect to see values
		cachedAliases, err := r.ListResolvableAliases(ctx, at.Id)
		require.NoError(t, err)
		assert.ElementsMatch(t, retAl[:3], cachedAliases.ResolvableAliases)
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
			WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testStaticResourceRetrievalFuncForId[*aliases.Alias](t, nil, nil))),
			WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc[*sessions.Session](t, nil, nil))),
			WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc[*targets.Target](t,
				[][]*targets.Target{
					retTargets[:3],
					retTargets[3:],
				},
				[][]string{
					nil,
					{retTargets[0].Id, retTargets[1].Id},
				},
			))),
		}
		assert.NoError(t, rs.Refresh(ctx, opts...))

		cachedTargets, err := r.ListTargets(ctx, at.Id)
		assert.NoError(t, err)
		assert.ElementsMatch(t, retTargets[:3], cachedTargets.Targets)

		// Second call removes the first 2 resources from the cache and adds the last
		assert.NoError(t, rs.Refresh(ctx, opts...))
		cachedTargets, err = r.ListTargets(ctx, at.Id)
		assert.NoError(t, err)
		assert.ElementsMatch(t, retTargets[2:], cachedTargets.Targets)
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
			WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testStaticResourceRetrievalFuncForId[*aliases.Alias](t, nil, nil))),
			WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc[*targets.Target](t, nil, nil))),
			WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc[*sessions.Session](t,
				[][]*sessions.Session{
					retSess[:3],
					retSess[3:],
				},
				[][]string{
					nil,
					{retSess[0].Id, retSess[1].Id},
				},
			))),
		}
		assert.NoError(t, rs.Refresh(ctx, opts...))
		cachedSessions, err := r.ListSessions(ctx, at.Id)
		assert.NoError(t, err)
		assert.ElementsMatch(t, retSess[:3], cachedSessions.Sessions)

		// Second call removes the first 2 resources from the cache and adds the last
		assert.NoError(t, rs.Refresh(ctx, opts...))
		cachedSessions, err = r.ListSessions(ctx, at.Id)
		assert.NoError(t, err)
		assert.ElementsMatch(t, retSess[2:], cachedSessions.Sessions)
	})

	t.Run("set aliases", func(t *testing.T) {
		s, err := db.Open(ctx)
		require.NoError(t, err)
		r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(boundaryAuthTokens))
		require.NoError(t, err)
		rs, err := NewRefreshService(ctx, r, hclog.Default(), 0, 0)
		require.NoError(t, err)
		require.NoError(t, r.AddKeyringToken(ctx, boundaryAddr, KeyringToken{KeyringType: "k", TokenName: "t", AuthTokenId: at.Id}))

		retAls := []*aliases.Alias{
			alias("1"),
			alias("2"),
			alias("3"),
			alias("4"),
		}
		opts := []Option{
			WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc[*sessions.Session](t, nil, nil))),
			WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc[*targets.Target](t, nil, nil))),
			WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testStaticResourceRetrievalFuncForId[*aliases.Alias](t,
				[][]*aliases.Alias{
					retAls[:3],
					retAls[3:],
				},
				[][]string{
					nil,
					{retAls[0].Id, retAls[1].Id},
				},
			))),
		}
		assert.NoError(t, rs.Refresh(ctx, opts...))
		cachedAliases, err := r.ListResolvableAliases(ctx, at.Id)
		assert.NoError(t, err)
		assert.ElementsMatch(t, retAls[:3], cachedAliases.ResolvableAliases)

		// Second call removes the first 2 resources from the cache and adds the last
		assert.NoError(t, rs.Refresh(ctx, opts...))
		cachedAliases, err = r.ListResolvableAliases(ctx, at.Id)
		assert.NoError(t, err)
		assert.ElementsMatch(t, retAls[2:], cachedAliases.ResolvableAliases)
	})

	t.Run("error propagates up", func(t *testing.T) {
		s, err := db.Open(ctx)
		require.NoError(t, err)
		r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(boundaryAuthTokens))
		require.NoError(t, err)
		rs, err := NewRefreshService(ctx, r, hclog.NewNullLogger(), 0, 0)
		require.NoError(t, err)
		require.NoError(t, r.AddKeyringToken(ctx, boundaryAddr, KeyringToken{KeyringType: "k", TokenName: "t", AuthTokenId: at.Id}))

		innerErr := errors.New("test error")
		err = rs.Refresh(ctx,
			WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testStaticResourceRetrievalFuncForId[*aliases.Alias](t, nil, nil))),
			WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc[*sessions.Session](t, nil, nil))),
			WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(func(ctx context.Context, addr, token string, refreshTok RefreshTokenValue) ([]*targets.Target, []string, RefreshTokenValue, error) {
				require.Equal(t, boundaryAddr, addr)
				require.Equal(t, at.Token, token)
				return nil, nil, "", innerErr
			})))
		assert.ErrorContains(t, err, innerErr.Error())
		err = rs.Refresh(ctx,
			WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testStaticResourceRetrievalFuncForId[*aliases.Alias](t, nil, nil))),
			WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc[*targets.Target](t, nil, nil))),
			WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(func(ctx context.Context, addr, token string, refreshTok RefreshTokenValue) ([]*sessions.Session, []string, RefreshTokenValue, error) {
				require.Equal(t, boundaryAddr, addr)
				require.Equal(t, at.Token, token)
				return nil, nil, "", innerErr
			})))
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

		require.NoError(t, rs.Refresh(ctx,
			WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testStaticResourceRetrievalFuncForId[*aliases.Alias](t, nil, nil))),
			WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc[*sessions.Session](t, nil, nil))),
			WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc[*targets.Target](t, nil, nil)))))

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
			WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testNoRefreshRetrievalFuncForId[*aliases.Alias](t))),
			WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testNoRefreshRetrievalFunc[*sessions.Session](t))),
			WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testNoRefreshRetrievalFunc[*targets.Target](t)))))

		got, err := r.ListTargets(ctx, at.Id)
		require.NoError(t, err)
		assert.Empty(t, got.Targets)
		assert.Empty(t, got.ResolvableAliases)
		assert.Empty(t, got.Sessions)
		assert.False(t, got.Incomplete)

		err = rs.Refresh(ctx,
			WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testNoRefreshRetrievalFuncForId[*aliases.Alias](t))),
			WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testNoRefreshRetrievalFunc[*sessions.Session](t))),
			WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testNoRefreshRetrievalFunc[*targets.Target](t))))
		assert.ErrorIs(t, err, ErrRefreshNotSupported)

		got, err = r.ListTargets(ctx, at.Id)
		require.NoError(t, err)
		assert.Empty(t, got.Targets)
		assert.Empty(t, got.ResolvableAliases)
		assert.Empty(t, got.Sessions)
		assert.False(t, got.Incomplete)

		// now a full fetch will work since the user has resources and no refresh token
		assert.NoError(t, rs.RecheckCachingSupport(ctx,
			WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testNoRefreshRetrievalFuncForId[*aliases.Alias](t))),
			WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testNoRefreshRetrievalFunc[*sessions.Session](t))),
			WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testNoRefreshRetrievalFunc[*targets.Target](t)))))
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
			WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testNoRefreshRetrievalFuncForId[*aliases.Alias](t))),
			WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testNoRefreshRetrievalFunc[*targets.Target](t))),
			WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testNoRefreshRetrievalFunc[*sessions.Session](t)))))

		got, err := r.ListSessions(ctx, at.Id)
		require.NoError(t, err)
		assert.Empty(t, got.Targets)
		assert.Empty(t, got.ResolvableAliases)
		assert.Empty(t, got.Sessions)
		assert.False(t, got.Incomplete)

		err = rs.Refresh(ctx,
			WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testNoRefreshRetrievalFuncForId[*aliases.Alias](t))),
			WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testNoRefreshRetrievalFunc[*targets.Target](t))),
			WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testNoRefreshRetrievalFunc[*sessions.Session](t))))
		assert.ErrorIs(t, err, ErrRefreshNotSupported)

		got, err = r.ListSessions(ctx, at.Id)
		require.NoError(t, err)
		assert.Empty(t, got.Targets)
		assert.Empty(t, got.ResolvableAliases)
		assert.Empty(t, got.Sessions)
		assert.False(t, got.Incomplete)

		assert.NoError(t, rs.RecheckCachingSupport(ctx,
			WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testNoRefreshRetrievalFuncForId[*aliases.Alias](t))),
			WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testNoRefreshRetrievalFunc[*targets.Target](t))),
			WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testNoRefreshRetrievalFunc[*sessions.Session](t)))))
		got, err = r.ListSessions(ctx, at.Id)
		require.NoError(t, err)
		assert.Empty(t, got.Targets)
		assert.Empty(t, got.ResolvableAliases)
		assert.Empty(t, got.Sessions)
		assert.False(t, got.Incomplete)
	})

	t.Run("aliases", func(t *testing.T) {
		s, err := db.Open(ctx)
		require.NoError(t, err)
		r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(boundaryAuthTokens))
		require.NoError(t, err)
		rs, err := NewRefreshService(ctx, r, hclog.Default(), 0, 0)
		require.NoError(t, err)
		require.NoError(t, r.AddKeyringToken(ctx, boundaryAddr, KeyringToken{KeyringType: "k", TokenName: "t", AuthTokenId: at.Id}))

		assert.NoError(t, rs.RecheckCachingSupport(ctx,
			WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testNoRefreshRetrievalFuncForId[*aliases.Alias](t))),
			WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testNoRefreshRetrievalFunc[*targets.Target](t))),
			WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testNoRefreshRetrievalFunc[*sessions.Session](t)))))

		got, err := r.ListResolvableAliases(ctx, at.Id)
		require.NoError(t, err)
		assert.Empty(t, got.Targets)
		assert.Empty(t, got.ResolvableAliases)
		assert.Empty(t, got.Sessions)
		assert.False(t, got.Incomplete)

		err = rs.Refresh(ctx,
			WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testNoRefreshRetrievalFuncForId[*aliases.Alias](t))),
			WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testNoRefreshRetrievalFunc[*targets.Target](t))),
			WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testNoRefreshRetrievalFunc[*sessions.Session](t))))
		assert.ErrorIs(t, err, ErrRefreshNotSupported)

		got, err = r.ListResolvableAliases(ctx, at.Id)
		require.NoError(t, err)
		assert.Empty(t, got.Targets)
		assert.Empty(t, got.ResolvableAliases)
		assert.Empty(t, got.Sessions)
		assert.False(t, got.Incomplete)

		assert.NoError(t, rs.RecheckCachingSupport(ctx,
			WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testNoRefreshRetrievalFuncForId[*aliases.Alias](t))),
			WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testNoRefreshRetrievalFunc[*targets.Target](t))),
			WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testNoRefreshRetrievalFunc[*sessions.Session](t)))))
		got, err = r.ListResolvableAliases(ctx, at.Id)
		require.NoError(t, err)
		assert.Empty(t, got.Targets)
		assert.Empty(t, got.ResolvableAliases)
		assert.Empty(t, got.Sessions)
		assert.False(t, got.Incomplete)
	})

	t.Run("error propagates up", func(t *testing.T) {
		s, err := db.Open(ctx)
		require.NoError(t, err)
		r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(boundaryAuthTokens))
		require.NoError(t, err)
		rs, err := NewRefreshService(ctx, r, hclog.NewNullLogger(), 0, 0)
		require.NoError(t, err)
		require.NoError(t, r.AddKeyringToken(ctx, boundaryAddr, KeyringToken{KeyringType: "k", TokenName: "t", AuthTokenId: at.Id}))

		err = rs.Refresh(ctx,
			WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testNoRefreshRetrievalFuncForId[*aliases.Alias](t))),
			WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testNoRefreshRetrievalFunc[*targets.Target](t))),
			WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testNoRefreshRetrievalFunc[*sessions.Session](t))))
		assert.ErrorIs(t, err, ErrRefreshNotSupported)

		innerErr := errors.New("test error")
		err = rs.RecheckCachingSupport(ctx,
			WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testNoRefreshRetrievalFuncForId[*aliases.Alias](t))),
			WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testNoRefreshRetrievalFunc[*sessions.Session](t))),
			WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(func(ctx context.Context, addr, token string, refreshTok RefreshTokenValue) ([]*targets.Target, []string, RefreshTokenValue, error) {
				require.Equal(t, boundaryAddr, addr)
				require.Equal(t, at.Token, token)
				return nil, nil, "", innerErr
			})))
		assert.ErrorContains(t, err, innerErr.Error())

		err = rs.RecheckCachingSupport(ctx,
			WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testNoRefreshRetrievalFuncForId[*aliases.Alias](t))),
			WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testNoRefreshRetrievalFunc[*sessions.Session](t))),
			WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(func(ctx context.Context, addr, token string, refreshTok RefreshTokenValue) ([]*targets.Target, []string, RefreshTokenValue, error) {
				require.Equal(t, boundaryAddr, addr)
				require.Equal(t, at.Token, token)
				return nil, nil, "", innerErr
			})))
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
			WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testNoRefreshRetrievalFuncForId[*aliases.Alias](t))),
			WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testNoRefreshRetrievalFunc[*targets.Target](t))),
			WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testNoRefreshRetrievalFunc[*sessions.Session](t))))
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
			WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testNoRefreshRetrievalFuncForId[*aliases.Alias](t))),
			WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testNoRefreshRetrievalFunc[*sessions.Session](t))),
			WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testNoRefreshRetrievalFunc[*targets.Target](t))))
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

func alias(suffix string) *aliases.Alias {
	return &aliases.Alias{
		Id:    fmt.Sprintf("alt_%s", suffix),
		Type:  "target",
		Value: fmt.Sprintf("value%s", suffix),
	}
}
