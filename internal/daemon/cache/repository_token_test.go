// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ringToken is a test struct used to group a keyring type and token name
// so it can be used in an authtoken lookup function.
type ringToken struct {
	k string
	t string
}

func mapBasedAuthTokenLookup(m map[ringToken]*authtokens.AuthToken) func(k, t string) *authtokens.AuthToken {
	return func(k, t string) *authtokens.AuthToken {
		return m[ringToken{k, t}]
	}
}

func testAuthTokenLookup(k, t string) *authtokens.AuthToken {
	return &authtokens.AuthToken{
		Id:           fmt.Sprintf("at_%s", t),
		Token:        fmt.Sprintf("at_%s_%s", t, k),
		UserId:       fmt.Sprintf("u_%s", t),
		AuthMethodId: fmt.Sprintf("ampw_%s", t),
		AccountId:    fmt.Sprintf("acctpw_%s", t),
	}
}

func TestRepository_AddKeyringToken(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx)
	require.NoError(t, err)

	r, err := NewRepository(ctx, s, testAuthTokenLookup)
	require.NoError(t, err)

	keyring := "keyring"
	tokenName := "token"
	authTokenId := testAuthTokenLookup(keyring, tokenName).Id

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
				AuthTokenId: authTokenId,
			},
			errorContains: "",
		},
		{
			name: "missing address",
			kt: KeyringToken{
				KeyringType: keyring,
				TokenName:   tokenName,
				AuthTokenId: authTokenId,
			},
			errorContains: "boundary address is empty",
		},
		{
			name: "missing token",
			addr: "address",
			kt: KeyringToken{
				KeyringType: keyring,
				AuthTokenId: authTokenId,
			},
			errorContains: "token name is empty",
		},
		{
			name: "missing keyring type",
			addr: "address",
			kt: KeyringToken{
				TokenName:   tokenName,
				AuthTokenId: authTokenId,
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

func TestRepository_AddToken_EvictsOverLimit(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx)
	require.NoError(t, err)

	r, err := NewRepository(ctx, s, testAuthTokenLookup)
	require.NoError(t, err)

	addr := "address"
	kt := KeyringToken{KeyringType: "keyring", TokenName: "token"}
	at := testAuthTokenLookup(kt.KeyringType, kt.TokenName)
	kt.AuthTokenId = at.Id

	assert.NoError(t, r.AddKeyringToken(ctx, addr, kt))
	assert.NoError(t, r.AddKeyringToken(ctx, addr, kt))

	lastKtAdded := kt
	for i := 0; i < usersLimit; i++ {
		kr := fmt.Sprintf("%s%d", kt.KeyringType, i)
		tn := fmt.Sprintf("%s%d", kt.TokenName, i)
		ikt := KeyringToken{KeyringType: kr, TokenName: tn}
		at := testAuthTokenLookup(kr, tn)
		ikt.AuthTokenId = at.Id
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

func TestRepository_AddToken_AddingExistingUpdatesLastAccessedTime(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx)
	require.NoError(t, err)
	addr := "someaddr"

	r, err := NewRepository(ctx, s, testAuthTokenLookup)
	require.NoError(t, err)

	p1 := KeyringToken{
		TokenName:   "default",
		KeyringType: "keyring",
	}
	at1 := testAuthTokenLookup(p1.KeyringType, p1.TokenName)
	p1.AuthTokenId = at1.Id
	assert.NoError(t, r.AddKeyringToken(ctx, addr, p1))
	p2 := KeyringToken{
		TokenName:   "default2",
		KeyringType: "keyring",
	}
	at2 := testAuthTokenLookup(p2.KeyringType, p2.TokenName)
	p2.AuthTokenId = at2.Id
	assert.NoError(t, r.AddKeyringToken(ctx, addr, p2))

	time.Sleep(10 * time.Millisecond)
	assert.NoError(t, r.AddKeyringToken(ctx, addr, p1))

	gotP1, err := r.LookupToken(ctx, p1.AuthTokenId)
	require.NoError(t, err)
	require.NotNil(t, gotP1)
	gotP2, err := r.LookupToken(ctx, p2.AuthTokenId)
	require.NoError(t, err)
	require.NotNil(t, gotP2)

	assert.Greater(t, gotP1.LastAccessedTime, gotP2.LastAccessedTime)
}

func TestRepository_ListTokens(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx)
	require.NoError(t, err)

	r, err := NewRepository(ctx, s, testAuthTokenLookup)
	require.NoError(t, err)

	addr := "address"
	kt := KeyringToken{KeyringType: "keyring", TokenName: "token"}
	at := testAuthTokenLookup(kt.KeyringType, kt.TokenName)
	kt.AuthTokenId = at.Id
	u := &user{
		Id:      at.UserId,
		Address: addr,
	}

	t.Run("no token", func(t *testing.T) {
		gotP, err := r.listTokens(ctx, u)
		assert.NoError(t, err)
		assert.Empty(t, gotP)
	})

	ktTokenCount := 15

	for i := 0; i < ktTokenCount; i++ {
		thisKeyringType := fmt.Sprintf("%s%d", kt.KeyringType, i)
		ikt := KeyringToken{KeyringType: thisKeyringType, TokenName: kt.TokenName}
		at := testAuthTokenLookup(ikt.KeyringType, ikt.TokenName)
		ikt.AuthTokenId = at.Id
		require.NoError(t, r.AddKeyringToken(ctx, addr, ikt))
	}

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
	s, err := Open(ctx)
	require.NoError(t, err)

	r, err := NewRepository(ctx, s, testAuthTokenLookup)
	require.NoError(t, err)

	t.Run("delete non existing", func(t *testing.T) {
		assert.ErrorContains(t, r.deleteKeyringToken(ctx, KeyringToken{KeyringType: "Unknown", TokenName: "Unknown"}), "not found")
	})

	t.Run("delete existing", func(t *testing.T) {
		addr := "address"
		kt := KeyringToken{KeyringType: "keyring", TokenName: "token"}
		at := testAuthTokenLookup(kt.KeyringType, kt.TokenName)
		kt.AuthTokenId = at.Id
		assert.NoError(t, r.AddKeyringToken(ctx, addr, kt))
		p, err := r.LookupToken(ctx, kt.AuthTokenId)
		require.NoError(t, err)
		require.NotNil(t, p)

		assert.NoError(t, r.deleteKeyringToken(ctx, kt))

		got, err := r.LookupToken(ctx, kt.AuthTokenId)
		require.NoError(t, err)
		require.Nil(t, got)
	})
}

func TestRepository_LookupToken(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx)
	require.NoError(t, err)

	r, err := NewRepository(ctx, s, testAuthTokenLookup)
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
		addr := "address"
		kt := KeyringToken{KeyringType: "keyring", TokenName: "token"}
		at := testAuthTokenLookup(kt.KeyringType, kt.TokenName)
		kt.AuthTokenId = at.Id

		assert.NoError(t, r.AddKeyringToken(ctx, addr, kt))
		p, err := r.LookupToken(ctx, kt.AuthTokenId)
		assert.NoError(t, err)
		assert.NotEmpty(t, p)
	})

	t.Run("withUpdateLastAccessedTime", func(t *testing.T) {
		addr := "address"
		kt := KeyringToken{KeyringType: "keyring", TokenName: "token"}
		at := testAuthTokenLookup(kt.KeyringType, kt.TokenName)
		kt.AuthTokenId = at.Id

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
	s, err := Open(ctx)
	require.NoError(t, err)

	atMap := make(map[ringToken]*authtokens.AuthToken)
	atLookupFn := mapBasedAuthTokenLookup(atMap)

	r, err := NewRepository(ctx, s, atLookupFn)
	require.NoError(t, err)

	staleTime := time.Now().Add(-(tokenStalenessLimit + 1*time.Hour))
	oldNotStaleTime := time.Now().Add(-(tokenStalenessLimit - 1*time.Hour))

	userId := "userId"
	addr := "address"
	keyringType := "keyring"
	tokenName := "token"
	authTokenId := "authTokenId"
	for i := 0; i < usersLimit; i++ {
		iKeyringType := fmt.Sprintf("%s%d", keyringType, i)
		iTokenName := fmt.Sprintf("%s%d", tokenName, i)
		iAuthTokenId := fmt.Sprintf("%s%d", authTokenId, i)

		kt := KeyringToken{
			KeyringType: iKeyringType,
			TokenName:   iTokenName,
			AuthTokenId: iAuthTokenId,
		}

		atMap[ringToken{kt.KeyringType, kt.TokenName}] = &authtokens.AuthToken{
			Id:     kt.AuthTokenId,
			UserId: userId,
			Token:  fmt.Sprintf("%s_sometokenvalue", kt.AuthTokenId),
		}

		assert.NoError(t, r.AddKeyringToken(ctx, addr, kt))
		p := &AuthToken{
			UserId: userId,
			Id:     kt.AuthTokenId,
		}
		switch i % 3 {
		case 0:
			p.LastAccessedTime = staleTime
			_, err := r.rw.Update(ctx, p, []string{"LastAccessedTime"}, nil)
			require.NoError(t, err)
		case 1:
			p.LastAccessedTime = oldNotStaleTime
			_, err := r.rw.Update(ctx, p, []string{"LastAccessedTime"}, nil)
			require.NoError(t, err)
		}
	}

	assert.NoError(t, r.removeStaleTokens(ctx))
	lAt, err := r.listTokens(ctx, &user{
		Id:      userId,
		Address: addr,
	})
	assert.NoError(t, err)
	assert.Len(t, lAt, usersLimit*2/3)
}
