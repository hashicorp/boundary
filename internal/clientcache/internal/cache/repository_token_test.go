// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"database/sql/driver"
	stderrors "errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api/aliases"
	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/api/targets"
	cachedb "github.com/hashicorp/boundary/internal/clientcache/internal/db"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/go-dbw"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
)

func TestRepository_AddKeyringToken(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)

	addr := "address"
	u := user{
		Id:      "u1",
		Address: addr,
	}
	at := &authtokens.AuthToken{
		Id:     "at_1",
		Token:  "at_1_token",
		UserId: u.Id,
	}
	// used to test mismatched user ids between keyring and cache
	mismatchingAt := &authtokens.AuthToken{
		Id:     "at_mismatch",
		Token:  "at_mismatch_token",
		UserId: u.Id,
	}
	boundaryAuthTokens := []*authtokens.AuthToken{at, mismatchingAt}
	keyring := "k"
	tokenName := "t"
	atMap := make(map[ringToken]*authtokens.AuthToken)
	atMap[ringToken{keyring, tokenName}] = at
	atMap[ringToken{"mismatch", "mismatch"}] = mismatchingAt
	r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(boundaryAuthTokens))
	require.NoError(t, err)

	t.Run("userid mismatch between db and keyring", func(t *testing.T) {
		require.NoError(t, r.AddKeyringToken(ctx, "address", KeyringToken{
			KeyringType: "mismatch",
			TokenName:   "mismatch",
			AuthTokenId: mismatchingAt.Id,
		}))

		mismatchingAt.UserId = "changedToMismatch"
		assert.ErrorContains(t, r.AddKeyringToken(ctx, "address", KeyringToken{
			KeyringType: "mismatch",
			TokenName:   "mismatch",
			AuthTokenId: mismatchingAt.Id,
		}), "user id doesn't match what is specified in the stored auth token")
	})

	errCases := []struct {
		name          string
		addr          string
		kt            KeyringToken
		errorContains string
	}{
		{
			name: "success",
			addr: "address",
			kt: KeyringToken{
				KeyringType: keyring,
				TokenName:   tokenName,
				AuthTokenId: at.Id,
			},
			errorContains: "",
		},
		{
			name: "not in keyring",
			addr: "address",
			kt: KeyringToken{
				KeyringType: keyring,
				TokenName:   "unknowntokenname",
				AuthTokenId: at.Id,
			},
			errorContains: "unable to find token in the keyring specified",
		},
		{
			name: "missing address",
			kt: KeyringToken{
				KeyringType: keyring,
				TokenName:   tokenName,
				AuthTokenId: at.Id,
			},
			errorContains: "boundary address is empty",
		},
		{
			name: "missing token",
			addr: "address",
			kt: KeyringToken{
				KeyringType: keyring,
				AuthTokenId: at.Id,
			},
			errorContains: "token name is empty",
		},
		{
			name: "missing keyring type",
			addr: "address",
			kt: KeyringToken{
				TokenName:   tokenName,
				AuthTokenId: at.Id,
			},
			errorContains: "keyring type is empty",
		},
		{
			name: "missing auth token id",
			addr: "address",
			kt: KeyringToken{
				KeyringType: keyring,
				TokenName:   tokenName,
			},
			errorContains: "boundary auth token id is empty",
		},
		{
			name: "unmatching auth token id",
			addr: "address",
			kt: KeyringToken{
				KeyringType: keyring,
				TokenName:   tokenName,
				AuthTokenId: "wrong auth token id",
			},
			errorContains: "provided auth token id doesn't match",
		},
	}

	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			err := r.AddKeyringToken(ctx, tc.addr, tc.kt)
			if tc.errorContains == "" {
				require.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tc.errorContains)
			}
		})
	}

	t.Run("When the keyring function errors", func(t *testing.T) {
		keyringFn := func(keyring, tokenName string) (*authtokens.AuthToken, error) {
			return nil, stderrors.New("keyring lookup function failed")
		}
		r, err := NewRepository(ctx, s, &sync.Map{}, keyringFn, sliceBasedAuthTokenBoundaryReader(boundaryAuthTokens))
		require.NoError(t, err)

		err = r.AddKeyringToken(ctx, "address", KeyringToken{
			KeyringType: "k",
			TokenName:   "t",
			AuthTokenId: "at_1",
		})
		assert.ErrorContains(t, err, "keyring lookup function failed")
	})
}

func TestRepository_AddRawToken(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)

	at := &authtokens.AuthToken{
		Id:     "at_1",
		Token:  "at_1_token",
		UserId: "u1",
	}
	existingAt := &authtokens.AuthToken{
		Id:     "at_existing",
		Token:  "at_existing_token",
		UserId: "u2",
	}
	boundaryAuthTokens := []*authtokens.AuthToken{at, existingAt}
	r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(map[ringToken]*authtokens.AuthToken{}), sliceBasedAuthTokenBoundaryReader(boundaryAuthTokens))
	require.NoError(t, err)

	t.Run("mismatched userid between memory and db", func(t *testing.T) {
		require.NoError(t, r.AddRawToken(ctx, "address", existingAt.Token))
		loadedExistingV, loaded := r.idToKeyringlessAuthToken.Load(existingAt.Id)
		require.True(t, loaded)
		loadedExistingAt := loadedExistingV.(*authtokens.AuthToken)
		loadedExistingAt.UserId = "mismatchingUserId"
		r.idToKeyringlessAuthToken.Store(existingAt.Id, loadedExistingAt)

		err := r.AddRawToken(ctx, "address", loadedExistingAt.Token)
		assert.Error(t, err)
		assert.ErrorContains(t, err, "user id doesn't match what is specified in the stored auth token")
	})

	errCases := []struct {
		name          string
		addr          string
		rawAt         string
		errorContains string
	}{
		{
			name:          "success",
			addr:          "address",
			rawAt:         at.Token,
			errorContains: "",
		},
		{
			name:          "missing address",
			rawAt:         at.Token,
			errorContains: "boundary address is empty",
		},
		{
			name:          "missing token",
			addr:          "address",
			errorContains: "auth token is empty",
		},
		{
			name:          "malformed auth token",
			addr:          "address",
			rawAt:         fmt.Sprintf("%s_extraunderscore", at.Token),
			errorContains: "boundary auth token is is malformed",
		},
		{
			name:          "not found in boundary",
			addr:          "address",
			rawAt:         "at_123_notfoundinboundary",
			errorContains: "not found",
		},
	}

	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			err := r.AddRawToken(ctx, tc.addr, tc.rawAt)
			if tc.errorContains == "" {
				require.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tc.errorContains)
			}
		})
	}
}

func TestRepository_AddToken_EvictsOverLimitUsers(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)

	boundaryAuthTokens := []*authtokens.AuthToken{
		{
			UserId: "user_base",
			Id:     "at_base",
			Token:  "at_base_token",
		},
	}
	for i := 0; i < usersLimit; i++ {
		iAt := &authtokens.AuthToken{
			UserId: fmt.Sprintf("user%d", i),
			Id:     fmt.Sprintf("at_%d", i),
		}
		iAt.Token = fmt.Sprintf("%s_token", iAt.Id)
		boundaryAuthTokens = append(boundaryAuthTokens, iAt)
	}

	atMap := make(map[ringToken]*authtokens.AuthToken)
	r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(boundaryAuthTokens))
	require.NoError(t, err)

	addr := "address"
	kt := KeyringToken{
		KeyringType: "keyring",
		TokenName:   "token",
		AuthTokenId: boundaryAuthTokens[0].Id,
	}
	atMap[ringToken{kt.KeyringType, kt.TokenName}] = boundaryAuthTokens[0]

	assert.NoError(t, r.AddKeyringToken(ctx, addr, kt))
	assert.NoError(t, r.AddKeyringToken(ctx, addr, kt))

	lastKtAdded := kt
	for i, at := range boundaryAuthTokens[1:] {
		kr := fmt.Sprintf("%s%d", kt.KeyringType, i)
		tn := fmt.Sprintf("%s%d", kt.TokenName, i)
		ikt := KeyringToken{KeyringType: kr, TokenName: tn, AuthTokenId: at.Id}

		atMap[ringToken{ikt.KeyringType, ikt.TokenName}] = at
		assert.NoError(t, r.AddKeyringToken(ctx, addr, ikt))
		lastKtAdded = ikt
	}

	// Lookup the first token added. It should have been deleted when the
	// associated user was evicted for being used the least recently.
	gotP, err := r.LookupToken(ctx, kt.AuthTokenId)
	assert.NoError(t, err)
	assert.Nil(t, gotP)

	gotP, err = r.LookupToken(ctx, lastKtAdded.AuthTokenId)
	assert.NoError(t, err)
	assert.NotEmpty(t, gotP)
}

func TestRepository_AddToken_EvictsOverLimit_Keyringless(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)

	boundaryAuthTokens := []*authtokens.AuthToken{
		{
			UserId: "user_base",
			Id:     "at_base",
			Token:  "at_base_token",
		},
	}
	for i := 0; i < usersLimit; i++ {
		iAt := &authtokens.AuthToken{
			UserId: fmt.Sprintf("user%d", i),
			Id:     fmt.Sprintf("at_%d", i),
		}
		iAt.Token = fmt.Sprintf("%s_token", iAt.Id)
		boundaryAuthTokens = append(boundaryAuthTokens, iAt)
	}

	atMap := make(map[ringToken]*authtokens.AuthToken)
	r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(boundaryAuthTokens))
	require.NoError(t, err)

	addr := "address"

	assert.NoError(t, r.AddRawToken(ctx, addr, boundaryAuthTokens[0].Token))
	assert.NoError(t, r.AddRawToken(ctx, addr, boundaryAuthTokens[0].Token))
	for _, at := range boundaryAuthTokens[1:] {
		assert.NoError(t, r.AddRawToken(ctx, addr, at.Token))
	}
	// Lookup the first persona added. It should have been evicted from the db
	// for being used the least recently. It is only removed from the db once
	// cleanAuthTokens is called.
	gotP, err := r.LookupToken(ctx, boundaryAuthTokens[0].Id)
	assert.NoError(t, err)
	assert.Nil(t, gotP)
	_, ok := r.idToKeyringlessAuthToken.Load(boundaryAuthTokens[0].Id)
	assert.True(t, ok)

	gotP, err = r.LookupToken(ctx, boundaryAuthTokens[len(boundaryAuthTokens)-1].Id)
	assert.NoError(t, err)
	assert.NotEmpty(t, gotP)
	_, ok = r.idToKeyringlessAuthToken.Load(boundaryAuthTokens[len(boundaryAuthTokens)-1].Id)
	assert.True(t, ok)

	assert.NoError(t, r.syncKeyringlessTokensWithDb(ctx))
	_, ok = r.idToKeyringlessAuthToken.Load(boundaryAuthTokens[0].Id)
	assert.False(t, ok)
}

func TestRepository_CleanAuthTokens(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)

	at := &authtokens.AuthToken{
		UserId: "user_base",
		Id:     "at_base",
		Token:  "at_base_token",
	}
	boundaryAuthTokens := []*authtokens.AuthToken{at}

	atMap := make(map[ringToken]*authtokens.AuthToken)
	r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(boundaryAuthTokens))
	require.NoError(t, err)
	assert.NoError(t, r.AddRawToken(ctx, "baddr", at.Token))
	_, present := r.idToKeyringlessAuthToken.Load(at.Id)
	assert.True(t, present)

	_, err = r.rw.Delete(ctx, &user{Id: at.UserId})
	require.NoError(t, err)

	_, present = r.idToKeyringlessAuthToken.Load(at.Id)
	assert.True(t, present)

	assert.NoError(t, r.syncKeyringlessTokensWithDb(ctx))

	_, present = r.idToKeyringlessAuthToken.Load(at.Id)
	assert.False(t, present)
}

func TestRepository_AddKeyringToken_AddingExistingUpdatesLastAccessedTime(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)

	addr := "address"
	at1 := &authtokens.AuthToken{
		Id:     "at_1",
		Token:  "at_1_token",
		UserId: "u_1",
	}
	kt1 := KeyringToken{
		TokenName:   "t1",
		KeyringType: "k1",
		AuthTokenId: at1.Id,
	}
	at2 := &authtokens.AuthToken{
		Id:     "at_2",
		Token:  "at_2_token",
		UserId: "u_2",
	}
	kt2 := KeyringToken{
		TokenName:   "t2",
		KeyringType: "k2",
		AuthTokenId: "at_2",
	}

	boundaryAuthTokens := []*authtokens.AuthToken{at1, at2}
	atMap := map[ringToken]*authtokens.AuthToken{
		{kt1.KeyringType, kt1.TokenName}: at1,
		{kt2.KeyringType, kt2.TokenName}: at2,
	}
	r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(boundaryAuthTokens))
	require.NoError(t, err)

	assert.NoError(t, r.AddKeyringToken(ctx, addr, kt1))
	assert.NoError(t, r.AddKeyringToken(ctx, addr, kt2))

	time.Sleep(10 * time.Millisecond)
	assert.NoError(t, r.AddKeyringToken(ctx, addr, kt1))

	gotP1, err := r.LookupToken(ctx, kt1.AuthTokenId)
	require.NoError(t, err)
	require.NotNil(t, gotP1)
	gotP2, err := r.LookupToken(ctx, kt2.AuthTokenId)
	require.NoError(t, err)
	require.NotNil(t, gotP2)

	assert.Greater(t, gotP1.LastAccessedTime, gotP2.LastAccessedTime)
}

func TestRepository_AddRawToken_AddingExistingUpdatesLastAccessedTime(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)

	addr := "address"
	at1 := &authtokens.AuthToken{
		Id:     "at_1",
		Token:  "at_1_token",
		UserId: "u_1",
	}
	at2 := &authtokens.AuthToken{
		Id:     "at_2",
		Token:  "at_2_token",
		UserId: "u_2",
	}

	boundaryAuthTokens := []*authtokens.AuthToken{at1, at2}
	atMap := map[ringToken]*authtokens.AuthToken{}
	r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(boundaryAuthTokens))
	require.NoError(t, err)

	assert.NoError(t, r.AddRawToken(ctx, addr, at1.Token))
	assert.NoError(t, r.AddRawToken(ctx, addr, at2.Token))

	time.Sleep(10 * time.Millisecond)
	assert.NoError(t, r.AddRawToken(ctx, addr, at1.Token))

	gotP1, err := r.LookupToken(ctx, at1.Id)
	require.NoError(t, err)
	require.NotNil(t, gotP1)
	gotP2, err := r.LookupToken(ctx, at2.Id)
	require.NoError(t, err)
	require.NotNil(t, gotP2)

	assert.Greater(t, gotP1.LastAccessedTime, gotP2.LastAccessedTime)
}

func TestRepository_ListTokens(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)

	addr := "address"
	u := &user{
		Id:      "u1",
		Address: addr,
	}
	at := &authtokens.AuthToken{
		Id:     "at_1",
		Token:  "at_1_token",
		UserId: u.Id,
	}

	atMap := make(map[ringToken]*authtokens.AuthToken)

	ktTokenCount := 15
	for i := 0; i < ktTokenCount; i++ {
		k := fmt.Sprintf("k%d", i)
		t := fmt.Sprintf("t%d", i)
		atMap[ringToken{k, t}] = at
	}

	r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(maps.Values(atMap)))
	require.NoError(t, err)

	for k, v := range atMap {
		require.NoError(t, r.AddKeyringToken(ctx, addr, KeyringToken{
			KeyringType: k.k,
			TokenName:   k.t,
			AuthTokenId: v.Id,
		}))
	}

	t.Run("no token", func(t *testing.T) {
		gotP, err := r.listTokens(ctx, &user{Id: "tokenless"})
		assert.NoError(t, err)
		assert.Empty(t, gotP)
	})

	t.Run("many tokens", func(t *testing.T) {
		gotAt, err := r.listTokens(ctx, u)
		assert.NoError(t, err)
		assert.Len(t, gotAt, 1)

		gotKrt, err := r.listKeyringTokens(ctx, gotAt[0])
		assert.NoError(t, err)
		assert.Len(t, gotKrt, ktTokenCount)
	})
}

func TestRepository_DeleteKeyringToken(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)

	addr := "address"
	at1 := &authtokens.AuthToken{
		Id:     "at_1",
		Token:  "at_1_token",
		UserId: "u_1",
	}
	kt1 := KeyringToken{
		TokenName:   "t1",
		KeyringType: "k1",
		AuthTokenId: at1.Id,
	}

	boundaryAuthTokens := []*authtokens.AuthToken{at1}
	atMap := map[ringToken]*authtokens.AuthToken{
		{kt1.KeyringType, kt1.TokenName}: at1,
	}
	r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(boundaryAuthTokens))
	require.NoError(t, err)

	t.Run("delete non existing", func(t *testing.T) {
		assert.ErrorContains(t, r.deleteKeyringToken(ctx, KeyringToken{KeyringType: "Unknown", TokenName: "Unknown"}), "not found")
	})

	t.Run("delete existing", func(t *testing.T) {
		assert.NoError(t, r.AddKeyringToken(ctx, addr, kt1))
		p, err := r.LookupToken(ctx, kt1.AuthTokenId)
		require.NoError(t, err)
		require.NotNil(t, p)

		assert.NoError(t, r.deleteKeyringToken(ctx, kt1))

		got, err := r.LookupToken(ctx, kt1.AuthTokenId)
		require.NoError(t, err)
		require.Nil(t, got)
	})
}

func TestRepository_LookupToken(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)

	addr := "address"
	at := &authtokens.AuthToken{
		Id:     "at_1",
		Token:  "at_1_token",
		UserId: "u_1",
	}
	kt := KeyringToken{
		TokenName:   "t1",
		KeyringType: "k1",
		AuthTokenId: at.Id,
	}

	boundaryAuthTokens := []*authtokens.AuthToken{at}
	atMap := map[ringToken]*authtokens.AuthToken{
		{kt.KeyringType, kt.TokenName}: at,
	}
	r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(boundaryAuthTokens))
	require.NoError(t, err)

	t.Run("empty token id", func(t *testing.T) {
		p, err := r.LookupToken(ctx, "")
		assert.ErrorContains(t, err, "auth token id is empty")
		assert.Nil(t, p)
	})
	t.Run("not found", func(t *testing.T) {
		p, err := r.LookupToken(ctx, "token")
		assert.NoError(t, err)
		assert.Nil(t, p)
	})
	t.Run("found", func(t *testing.T) {
		assert.NoError(t, r.AddKeyringToken(ctx, addr, kt))
		p, err := r.LookupToken(ctx, kt.AuthTokenId)
		assert.NoError(t, err)
		assert.NotEmpty(t, p)
	})

	t.Run("withUpdateLastAccessedTime", func(t *testing.T) {
		assert.NoError(t, r.AddKeyringToken(ctx, addr, kt))
		time.Sleep(1 * time.Millisecond)

		beforeP, err := r.LookupToken(ctx, kt.AuthTokenId, WithUpdateLastAccessedTime(true))
		assert.NoError(t, err)
		assert.NotEmpty(t, beforeP)

		afterP, err := r.LookupToken(ctx, kt.AuthTokenId)
		assert.NoError(t, err)
		assert.NotEmpty(t, afterP)
		assert.Greater(t, afterP.LastAccessedTime, beforeP.LastAccessedTime)
	})
}

func TestRepository_lookupUpUser(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)

	addr := "address"
	at := &authtokens.AuthToken{
		Id:     "at_1",
		Token:  "at_1_token",
		UserId: "u_1",
	}
	kt := KeyringToken{
		TokenName:   "t1",
		KeyringType: "k1",
		AuthTokenId: at.Id,
	}

	boundaryAuthTokens := []*authtokens.AuthToken{at}
	atMap := map[ringToken]*authtokens.AuthToken{
		{kt.KeyringType, kt.TokenName}: at,
	}
	r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(boundaryAuthTokens))
	require.NoError(t, err)
	assert.NoError(t, r.AddKeyringToken(ctx, addr, kt))

	t.Run("empty user id", func(t *testing.T) {
		u, err := r.lookupUser(ctx, "")
		assert.ErrorContains(t, err, "empty id")
		assert.Nil(t, u)
	})
	t.Run("not found user id", func(t *testing.T) {
		u, err := r.lookupUser(ctx, "notfound")
		assert.NoError(t, err)
		assert.Nil(t, u)
	})
	t.Run("found", func(t *testing.T) {
		u, err := r.lookupUser(ctx, at.UserId)
		assert.NoError(t, err)
		assert.Equal(t, &user{Id: at.UserId, Address: addr}, u)
	})
	t.Run("soft-deleted", func(t *testing.T) {
		at2 := &authtokens.AuthToken{
			Id:             "at_2",
			Token:          "at_2_token",
			UserId:         "u_2",
			ExpirationTime: time.Now().Add(1 * time.Minute), // not expired is required for this test
		}
		kt2 := KeyringToken{
			TokenName:   "t2",
			KeyringType: "k2",
			AuthTokenId: at2.Id,
		}
		addr2 := "address2"
		boundaryAuthTokens2 := []*authtokens.AuthToken{at2}
		atMap2 := map[ringToken]*authtokens.AuthToken{
			{kt2.KeyringType, kt2.TokenName}: at2,
		}
		m := &sync.Map{}
		r2, err := NewRepository(ctx, s, m, mapBasedAuthTokenKeyringLookup(atMap2), sliceBasedAuthTokenBoundaryReader(boundaryAuthTokens2))
		require.NoError(t, err)
		assert.NoError(t, r2.AddKeyringToken(ctx, addr2, kt2))

		rs, err := NewRefreshService(ctx, r2, hclog.NewNullLogger(), 0, 0)
		require.NoError(t, err)

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
		assert.NoError(t, rs.RefreshForSearch(ctx, at2.Id, Targets, opts...))
		// Now load up a few resources and a token, and trying again should
		// see the RefreshForSearch update more fields.
		assert.NoError(t, rs.Refresh(ctx, opts...))
		cachedTargets, err := r.ListTargets(ctx, at2.Id)
		assert.NoError(t, err)
		assert.ElementsMatch(t, retTargets[:3], cachedTargets.Targets)

		// should be found in cache (user_active)
		u2, err := r2.lookupUser(ctx, at2.UserId)
		assert.NoError(t, err)
		assert.Equal(t, &user{Id: at2.UserId, Address: addr2}, u2)
		u2, err = r2.lookupUser(ctx, at2.UserId)
		assert.NoError(t, err)
		assert.Equal(t, &user{Id: at2.UserId, Address: addr2}, u2)

		// should be found in underlying user table as well
		tu, err := testLookupUser(t, s, at2.UserId)
		assert.NoError(t, err)
		assert.Equal(t, &testUser{Id: at2.UserId, Address: addr2, DeletedAt: infinityValue}, tu)

		// there better be some refresh tokens
		tks, err := r2.listRefreshTokens(ctx, u2)
		assert.NoError(t, err)
		assert.NotEmpty(t, tks)

		// now delete the user's auth_token and be sure the user is still found
		// in the cache (table == "user" and not in "user_active")
		err = r2.deleteKeyringToken(ctx, kt2)
		require.NoError(t, err)

		currentTks, err := r2.listTokens(ctx, u2)
		require.NoError(t, err)
		assert.Empty(t, currentTks)

		// should no longer be an active user
		u2, err = r2.lookupUser(ctx, tu.Id)
		assert.NoError(t, err)
		assert.Empty(t, u2)

		// should still be found in underlying user table
		tu, err = testLookupUser(t, s, tu.Id)
		assert.NoError(t, err)
		assert.Equal(t, &testUser{Id: tu.Id, Address: tu.Address, DeletedAt: tu.DeletedAt}, tu)
	})
	t.Run("hard-deleted", func(t *testing.T) {
		at3 := &authtokens.AuthToken{
			Id:             "at_3",
			Token:          "at_3_token",
			UserId:         "u_3",
			ExpirationTime: time.Now().Add(1 * time.Minute), // not expired is required for this test
		}
		kt3 := KeyringToken{
			TokenName:   "t3",
			KeyringType: "k3",
			AuthTokenId: at3.Id,
		}
		addr3 := "address3"
		boundaryAuthTokens3 := []*authtokens.AuthToken{at3}
		atMap3 := map[ringToken]*authtokens.AuthToken{
			{kt3.KeyringType, kt3.TokenName}: at3,
		}
		m := &sync.Map{}
		r3, err := NewRepository(ctx, s, m, mapBasedAuthTokenKeyringLookup(atMap3), sliceBasedAuthTokenBoundaryReader(boundaryAuthTokens3))
		require.NoError(t, err)
		assert.NoError(t, r3.AddKeyringToken(ctx, addr3, kt3))

		// should be found in cache (user_active)
		u3, err := r3.lookupUser(ctx, at3.UserId)
		assert.NoError(t, err)
		assert.Equal(t, &user{Id: at3.UserId, Address: addr3}, u3)
		u3, err = r3.lookupUser(ctx, at3.UserId)
		assert.NoError(t, err)
		assert.Equal(t, &user{Id: at3.UserId, Address: addr3}, u3)

		// should be found in underlying user table as well
		tu, err := testLookupUser(t, s, at3.UserId)
		assert.NoError(t, err)
		assert.Equal(t, &testUser{Id: at3.UserId, Address: addr3, DeletedAt: infinityValue}, tu)

		// there better be some refresh tokens
		tks, err := r3.listRefreshTokens(ctx, u3)
		assert.NoError(t, err)
		assert.Empty(t, tks)

		// now delete the user's auth_token and be sure the user is not found
		// in the cache (not in either the "user" or "user_active" tables)
		err = r3.deleteKeyringToken(ctx, kt3)
		require.NoError(t, err)

		currentTks, err := r3.listTokens(ctx, u3)
		require.NoError(t, err)
		assert.Empty(t, currentTks)

		// should no longer be an active user
		u3, err = r3.lookupUser(ctx, tu.Id)
		assert.NoError(t, err)
		assert.Empty(t, u3)

		// should not be found in underlying user table
		_, err = testLookupUser(t, s, tu.Id)
		assert.Error(t, err)
		assert.ErrorIs(t, err, dbw.ErrRecordNotFound)
	})
}

// infinityValue represents a time.Time that is infinity
var infinityValue = infinityDate{
	Time:       time.Time{},
	IsInfinity: true,
}

// infinityDate is used to represent a time.Time that can be infinity, neg
// infinity or a regular time.Time
type infinityDate struct {
	Time          time.Time
	IsInfinity    bool
	IsNegInfinity bool
}

// sqliteDatetimeLayout defines the format for sqlite datetime ('YYYY-MM-DD HH:MM:SS.SSS')
const sqliteDatetimeLayout = "2006-01-02 15:04:05.999"

// Scan implements the sql.Scanner interface for infinityDate
func (d *infinityDate) Scan(value any) error {
	switch v := value.(type) {
	case string:
		if v == "infinity" {
			d.IsInfinity = true
			d.IsNegInfinity = false
			return nil
		} else if v == "-infinity" {
			d.IsNegInfinity = true
			d.IsInfinity = false
			return nil
		} else {
			parsedTime, err := time.Parse(sqliteDatetimeLayout, v)
			if err != nil {
				return err
			}
			d.Time = parsedTime
			d.IsInfinity = false
			d.IsNegInfinity = false
			return nil
		}
	case time.Time:
		d.Time = v
		d.IsInfinity = false
		d.IsNegInfinity = false
		return nil
	}
	return stderrors.New("unsupported data type for Date")
}

// Value implements the driver.Valuer interface for infinityDate
func (d infinityDate) Value() (driver.Value, error) {
	if d.IsInfinity {
		return "infinity", nil
	} else if d.IsNegInfinity {
		return "-infinity", nil
	}
	return d.Time.Format(sqliteDatetimeLayout), nil
}

// testUser is used by testLookupUser to lookup a user from the database and
// supports returning the user's DeletedAt time (soft delete).
type testUser struct {
	Id        string
	Address   string
	DeletedAt infinityDate
}

// testLookupUser is a helper function to lookup a user from the database in the
// underlying user table.
func testLookupUser(t *testing.T, conn any, id string) (*testUser, error) {
	t.Helper()
	var rw db.Reader
	switch v := conn.(type) {
	case *db.DB:
		rw = db.New(v)
	case db.Reader:
		rw = v
	}
	u := &testUser{
		Id: id,
	}
	err := rw.LookupById(context.Background(), u, db.WithTable("user"))
	switch {
	case err == nil:
		return u, nil
	default:
		return &testUser{}, err
	}
}

func TestRepository_RemoveStaleTokens(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)

	u := &user{
		Id:      "user",
		Address: "address",
	}
	at1 := &authtokens.AuthToken{
		Id:             "at_1",
		Token:          "at_1_token",
		UserId:         u.Id,
		ExpirationTime: time.Now().Add(1 * time.Minute),
	}
	kt1 := KeyringToken{
		TokenName:   "t1",
		KeyringType: "k1",
		AuthTokenId: at1.Id,
	}
	at2 := &authtokens.AuthToken{
		Id:             "at_2",
		Token:          "at_2_token",
		UserId:         u.Id,
		ExpirationTime: time.Now().Add(1 * time.Minute),
	}
	kt2 := KeyringToken{
		TokenName:   "t2",
		KeyringType: "k2",
		AuthTokenId: "at_2",
	}
	// this auth token expired a minute ago
	at3 := &authtokens.AuthToken{
		Id:             "at_3",
		Token:          "at_3_token",
		UserId:         u.Id,
		ExpirationTime: time.Now().Add(-(1 * time.Minute)),
	}
	kt3 := KeyringToken{
		TokenName:   "t3",
		KeyringType: "k3",
		AuthTokenId: "at_3",
	}

	boundaryAuthTokens := []*authtokens.AuthToken{at1, at2, at3}
	atMap := map[ringToken]*authtokens.AuthToken{
		{kt1.KeyringType, kt1.TokenName}: at1,
		{kt2.KeyringType, kt2.TokenName}: at2,
		{kt3.KeyringType, kt3.TokenName}: at3,
	}
	r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(boundaryAuthTokens))
	require.NoError(t, err)
	assert.NoError(t, r.AddKeyringToken(ctx, u.Address, kt1))
	assert.NoError(t, r.AddKeyringToken(ctx, u.Address, kt2))
	assert.NoError(t, r.AddKeyringToken(ctx, u.Address, kt3))

	staleTime := time.Now().Add(-(tokenStalenessLimit + 1*time.Hour))
	freshTime := time.Now().Add(-(tokenStalenessLimit - 1*time.Hour))

	freshAt := &AuthToken{
		Id:               at1.Id,
		LastAccessedTime: freshTime,
	}
	_, err = r.rw.Update(ctx, freshAt, []string{"LastAccessedTime"}, nil)
	require.NoError(t, err)
	anotherFreshAt := &AuthToken{
		Id:               at3.Id,
		LastAccessedTime: freshTime,
	}
	_, err = r.rw.Update(ctx, anotherFreshAt, []string{"LastAccessedTime"}, nil)
	require.NoError(t, err)

	staleAt := &AuthToken{
		Id:               at2.Id,
		LastAccessedTime: staleTime,
	}
	_, err = r.rw.Update(ctx, staleAt, []string{"LastAccessedTime"}, nil)
	require.NoError(t, err)

	lAt, err := r.listTokens(ctx, u)
	assert.NoError(t, err)
	assert.Len(t, lAt, 3)

	assert.NoError(t, r.cleanExpiredOrOrphanedAuthTokens(ctx))

	lAt, err = r.listTokens(ctx, u)
	assert.NoError(t, err)
	assert.Len(t, lAt, 1)
	assert.Equal(t, lAt[0].Id, at1.Id)
}

func TestCleanExpiredOrOrphanedAuthTokens_Errors(t *testing.T) {
	ctx := context.Background()

	err := cleanExpiredOrOrphanedAuthTokens(ctx, nil, &sync.Map{})
	assert.Error(t, err)
	assert.ErrorContains(t, err, "writer is nil")

	s, err := cachedb.Open(ctx)
	require.NoError(t, err)
	rw := db.New(s)

	err = cleanExpiredOrOrphanedAuthTokens(ctx, rw, &sync.Map{})
	assert.Error(t, err)
	assert.ErrorContains(t, err, "writer isn't part of an inflight transaction")

	_, err = rw.DoTx(ctx, 1, db.ExpBackoff{}, func(_ db.Reader, writer db.Writer) error {
		err := cleanExpiredOrOrphanedAuthTokens(ctx, writer, nil)
		assert.Error(t, err)
		assert.ErrorContains(t, err, "keyringless auth token map is nil")
		return nil
	})
	require.NoError(t, err)
}

func TestUpsertUserAndAuthToken(t *testing.T) {
	ctx := context.Background()

	s, err := cachedb.Open(ctx)
	require.NoError(t, err)
	rw := db.New(s)

	defaultAt := &authtokens.AuthToken{
		Id:     "at_123",
		Token:  "at_123_token",
		UserId: "u_123",
	}

	_, err = rw.DoTx(ctx, 1, db.ExpBackoff{}, func(txReader db.Reader, txWriter db.Writer) error {
		errorCases := []struct {
			name          string
			reader        db.Reader
			writer        db.Writer
			addr          string
			at            *authtokens.AuthToken
			errorContains string
		}{
			{
				name:          "nil reader",
				reader:        nil,
				writer:        txWriter,
				addr:          "address",
				at:            defaultAt,
				errorContains: "reader is nil",
			},
			{
				name:          "nil writer",
				reader:        txReader,
				writer:        nil,
				addr:          "address",
				at:            defaultAt,
				errorContains: "writer is nil",
			},
			{
				name:          "writer not in tx",
				reader:        txReader,
				writer:        rw,
				addr:          "address",
				at:            defaultAt,
				errorContains: "writer isn't part of an inflight transaction",
			},
			{
				name:          "empty address",
				reader:        txReader,
				writer:        txWriter,
				addr:          "",
				at:            defaultAt,
				errorContains: "boundary address is empty",
			},
			{
				name:          "auth token is nil",
				reader:        txReader,
				writer:        txWriter,
				addr:          "address",
				at:            nil,
				errorContains: "auth token is nil",
			},
			{
				name:   "auth token missing id",
				reader: txReader,
				writer: txWriter,
				addr:   "address",
				at: &authtokens.AuthToken{
					Token:  "at_123_token",
					UserId: "u_123",
				},
				errorContains: "auth token id is empty",
			},
			{
				name:   "auth token missing user id",
				reader: txReader,
				writer: txWriter,
				addr:   "address",
				at: &authtokens.AuthToken{
					Id:    "at_123",
					Token: "at_123_token",
				},
				errorContains: "auth token user id is empty",
			},
		}

		for _, tc := range errorCases {
			t.Run(tc.name, func(t *testing.T) {
				err := upsertUserAndAuthToken(ctx, tc.reader, tc.writer, tc.addr, tc.at)
				assert.Error(t, err)
				assert.ErrorContains(t, err, tc.errorContains)
			})
		}
		return nil
	})
	require.NoError(t, err)
	t.Run("hard-and-soft-delete-oldest-user", func(t *testing.T) {
		boundaryAuthTokens := make([]*authtokens.AuthToken, 0, usersLimit)
		atMap := map[ringToken]*authtokens.AuthToken{}
		m := &sync.Map{}

		// create usersLimit users to simulate the case where the user limit is
		// reached. The Tx is required because upsertUserAndAuthToken requires
		// an inflight transaction.
		_, err = rw.DoTx(ctx, 1, db.ExpBackoff{}, func(txReader db.Reader, txWriter db.Writer) error {
			for i := 1; i <= usersLimit; i++ {
				u := &user{
					Id:      fmt.Sprintf("u_%d", i),
					Address: fmt.Sprintf("address_%d", i),
				}
				at := &authtokens.AuthToken{
					Id:     fmt.Sprintf("at_%d", i),
					Token:  fmt.Sprintf("at_%d_token", i),
					UserId: u.Id,
				}
				boundaryAuthTokens = append(boundaryAuthTokens, at)
				atMap[ringToken{fmt.Sprintf("k_%d", i), fmt.Sprintf("t_%d", i)}] = at
				err := upsertUserAndAuthToken(ctx, txReader, txWriter, u.Address, at)
				require.NoError(t, err)

			}
			return nil
		})
		// verify that all the initial users were added
		repo, err := NewRepository(ctx, s, m, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(boundaryAuthTokens))
		require.NoError(t, err)
		for i := 1; i <= usersLimit; i++ {
			userId := fmt.Sprintf("u_%d", i)
			foundUser, err := repo.lookupUser(ctx, userId)
			require.NoError(t, err)
			_, err = testLookupUser(t, s, foundUser.Id)
			assert.NoError(t, err)
		}

		{
			// setup is done.  Let's add a new user and verify that the oldest
			// user is hard deleted
			_, err = rw.DoTx(ctx, 1, db.ExpBackoff{}, func(txReader db.Reader, txWriter db.Writer) error {
				// add a new user, which should trigger the hard deletion of the oldest user
				newUser := &user{
					Id:      "u_new",
					Address: "address_new",
				}
				newUserAt := &authtokens.AuthToken{
					Id:     "at_new",
					Token:  "at_new_token",
					UserId: newUser.Id,
				}
				err := upsertUserAndAuthToken(ctx, txReader, txWriter, newUser.Address, newUserAt)
				require.NoError(t, err)
				return nil
			})
			require.NoError(t, err)

			// verify that the oldest user was hard deleted
			foundUser, err := repo.lookupUser(ctx, "u_1")
			assert.NoError(t, err)
			assert.Empty(t, foundUser)
			foundTestUser, err := testLookupUser(t, s, "u_1")
			assert.Error(t, err)
			assert.Equal(t, &testUser{}, foundTestUser)
		}
		{
			//  Let's add a refresh token for the oldest user and then new user
			//  and verify that the oldest user is soft deleted
			rt := &refreshToken{
				UserId:       "u_2",
				ResourceType: "target",
				RefreshToken: "rt_2",
				CreateTime:   time.Now().Add(-24 * time.Hour),
				UpdateTime:   time.Now().Add(-24 * time.Hour),
			}
			err = repo.rw.Create(ctx, rt)
			require.NoError(t, err)

			_, err = rw.DoTx(ctx, 1, db.ExpBackoff{}, func(txReader db.Reader, txWriter db.Writer) error {
				// add a new user, which should trigger the soft deletion of the oldest user
				newUser := &user{
					Id:      "u_new_2",
					Address: "address_new_2",
				}
				newUserAt := &authtokens.AuthToken{
					Id:     "at_new_2",
					Token:  "at_new_token_2",
					UserId: newUser.Id,
				}
				err := upsertUserAndAuthToken(ctx, txReader, txWriter, newUser.Address, newUserAt)
				require.NoError(t, err)
				return nil
			})
			require.NoError(t, err)

			// verify that the oldest user was soft deleted
			foundUser, err := repo.lookupUser(ctx, "u_2")
			assert.NoError(t, err)
			assert.Empty(t, foundUser)
			// should not find the user in the underlying user table
			foundTestUser, err := testLookupUser(t, s, "u_2")
			assert.NoError(t, err)
			assert.NotEqual(t, &testUser{}, foundTestUser)
		}
	})
}
