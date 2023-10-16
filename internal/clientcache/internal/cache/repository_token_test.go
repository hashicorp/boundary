// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api/authtokens"
	cachedb "github.com/hashicorp/boundary/internal/clientcache/internal/db"
	"github.com/hashicorp/boundary/internal/db"
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

	rw.DoTx(ctx, 1, db.ExpBackoff{}, func(_ db.Reader, writer db.Writer) error {
		err := cleanExpiredOrOrphanedAuthTokens(ctx, writer, nil)
		assert.Error(t, err)
		assert.ErrorContains(t, err, "keyringless auth token map is nil")
		return nil
	})
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

	rw.DoTx(ctx, 1, db.ExpBackoff{}, func(txReader db.Reader, txWriter db.Writer) error {
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
}
