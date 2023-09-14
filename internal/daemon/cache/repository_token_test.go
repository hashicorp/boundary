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

func TestRepository_AddToken(t *testing.T) {
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
		tokenName     string
		keyringType   string
		authTokenId   string
		errorContains string
	}{
		{
			name:          "success",
			addr:          "address",
			tokenName:     tokenName,
			keyringType:   keyring,
			authTokenId:   authTokenId,
			errorContains: "",
		},
		{
			name:          "missing address",
			tokenName:     tokenName,
			keyringType:   keyring,
			authTokenId:   authTokenId,
			errorContains: "boundary address is empty",
		},
		{
			name:          "missing token",
			addr:          "address",
			keyringType:   keyring,
			authTokenId:   authTokenId,
			errorContains: "token name is empty",
		},
		{
			name:          "missing keyring type",
			addr:          "address",
			tokenName:     tokenName,
			authTokenId:   authTokenId,
			errorContains: "keyring type is empty",
		},
		{
			name:          "missing auth token id",
			addr:          "address",
			tokenName:     tokenName,
			keyringType:   keyring,
			errorContains: "boundary auth token id is empty",
		},
		{
			name:          "unmatching auth token id",
			addr:          "address",
			tokenName:     tokenName,
			keyringType:   keyring,
			authTokenId:   "a wrong value",
			errorContains: "provided auth token id doesn't match",
		},
	}

	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			err := r.AddToken(ctx, tc.addr, tc.tokenName, tc.keyringType, tc.authTokenId)
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
	keyringType := "keyring"
	tokenName := "token"
	at := testAuthTokenLookup(keyringType, tokenName)

	assert.NoError(t, r.AddToken(ctx, addr, tokenName, keyringType, at.Id))
	assert.NoError(t, r.AddToken(ctx, addr, tokenName, keyringType, at.Id))
	for i := 0; i < tokensLimit; i++ {
		kr := fmt.Sprintf("%s%d", keyringType, i)
		tn := fmt.Sprintf("%s%d", tokenName, i)
		at := testAuthTokenLookup(kr, tn)
		assert.NoError(t, r.AddToken(ctx, addr, tn, kr, at.Id))
	}
	// Lookup the first token added. It should have been evicted for being
	// used the least recently.
	gotP, err := r.LookupToken(ctx, tokenName, keyringType)
	assert.NoError(t, err)
	assert.Nil(t, gotP)

	gotP, err = r.LookupToken(ctx, tokenName+"0", keyringType+"0")
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

	p1 := &Token{
		TokenName:   "default",
		KeyringType: "keyring",
	}
	at1 := testAuthTokenLookup(p1.KeyringType, p1.TokenName)
	assert.NoError(t, r.AddToken(ctx, addr, p1.TokenName, p1.KeyringType,
		at1.Id))
	p2 := &Token{
		TokenName:   "default2",
		KeyringType: "keyring",
	}
	at2 := testAuthTokenLookup(p2.KeyringType, p2.TokenName)
	assert.NoError(t, r.AddToken(ctx, addr, p2.TokenName, p2.KeyringType, at2.Id))

	time.Sleep(10 * time.Millisecond)
	assert.NoError(t, r.AddToken(ctx, addr, p1.TokenName, p1.KeyringType, at1.Id))

	gotP1, err := r.LookupToken(ctx, p1.TokenName, p1.KeyringType)
	require.NoError(t, err)
	require.NotNil(t, gotP1)
	gotP2, err := r.LookupToken(ctx, p2.TokenName, p2.KeyringType)
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
	keyringType := "keyring"
	tokenName := "token"

	at := testAuthTokenLookup(keyringType, tokenName)
	u := &user{
		Id:      at.UserId,
		Address: addr,
	}

	t.Run("no token", func(t *testing.T) {
		gotP, err := r.listTokens(ctx, u)
		assert.NoError(t, err)
		assert.Empty(t, gotP)
	})

	tokenCount := 15

	for i := 0; i < tokenCount; i++ {
		thisKeyringType := fmt.Sprintf("%s%d", keyringType, i)
		at := testAuthTokenLookup(thisKeyringType, tokenName)
		require.NoError(t, r.AddToken(ctx, addr, tokenName, thisKeyringType, at.Id))
	}

	t.Run("many tokens", func(t *testing.T) {
		gotP, err := r.listTokens(ctx, u)
		assert.NoError(t, err)
		assert.Len(t, gotP, tokenCount)
	})
}

func TestRepository_DeleteToken(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx)
	require.NoError(t, err)

	r, err := NewRepository(ctx, s, testAuthTokenLookup)
	require.NoError(t, err)

	t.Run("delete non existing", func(t *testing.T) {
		assert.ErrorContains(t, r.deleteToken(ctx, &Token{KeyringType: "Unknown", TokenName: "Unknown"}), "not found")
	})

	t.Run("delete existing", func(t *testing.T) {
		addr := "address"
		keyringType := "keyring"
		tokenName := "token"
		at := testAuthTokenLookup(keyringType, tokenName)
		assert.NoError(t, r.AddToken(ctx, addr, tokenName, keyringType, at.Id))
		p, err := r.LookupToken(ctx, tokenName, keyringType)
		require.NoError(t, err)
		require.NotNil(t, p)

		assert.NoError(t, r.deleteToken(ctx, p))

		got, err := r.LookupToken(ctx, tokenName, keyringType)
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

	t.Run("empty token name", func(t *testing.T) {
		p, err := r.LookupToken(ctx, "", "keyring")
		assert.ErrorContains(t, err, "token name is empty")
		assert.Nil(t, p)
	})
	t.Run("empty keyring type", func(t *testing.T) {
		p, err := r.LookupToken(ctx, "token", "")
		assert.ErrorContains(t, err, "keyring type is empty")
		assert.Nil(t, p)
	})
	t.Run("not found", func(t *testing.T) {
		p, err := r.LookupToken(ctx, "token", "keyring")
		assert.NoError(t, err)
		assert.Nil(t, p)
	})
	t.Run("found", func(t *testing.T) {
		addr := "address"
		keyringType := "keyring"
		tokenName := "token"
		at := testAuthTokenLookup(keyringType, tokenName)

		assert.NoError(t, r.AddToken(ctx, addr, tokenName, keyringType, at.Id))
		p, err := r.LookupToken(ctx, tokenName, keyringType)
		assert.NoError(t, err)
		assert.NotEmpty(t, p)
	})
	t.Run("withAuthTokenId", func(t *testing.T) {
		addr := "address"
		keyringType := "keyring"
		tokenName := "token"
		at := testAuthTokenLookup(keyringType, tokenName)

		assert.NoError(t, r.AddToken(ctx, addr, tokenName, keyringType, at.Id))
		p, err := r.LookupToken(ctx, tokenName, keyringType, WithAuthTokenId(at.Id))
		assert.NoError(t, err)
		assert.NotEmpty(t, p)

		p, err = r.LookupToken(ctx, tokenName, keyringType, WithAuthTokenId("wrong"))
		assert.NoError(t, err)
		assert.Empty(t, p)
	})

	t.Run("withUpdateLastAccessedTime", func(t *testing.T) {
		addr := "address"
		keyringType := "keyring"
		tokenName := "token"
		at := testAuthTokenLookup(keyringType, tokenName)

		assert.NoError(t, r.AddToken(ctx, addr, tokenName, keyringType, at.Id))
		time.Sleep(1 * time.Millisecond)

		beforeP, err := r.LookupToken(ctx, tokenName, keyringType, WithUpdateLastAccessedTime(true))
		assert.NoError(t, err)
		assert.NotEmpty(t, beforeP)

		afterP, err := r.LookupToken(ctx, tokenName, keyringType)
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
	for i := 0; i < tokensLimit; i++ {
		iKeyringType := fmt.Sprintf("%s%d", keyringType, i)
		iTokenName := fmt.Sprintf("%s%d", tokenName, i)
		iAuthTokenId := fmt.Sprintf("%s%d", authTokenId, i)

		atMap[ringToken{iKeyringType, iTokenName}] = &authtokens.AuthToken{
			Id:     iAuthTokenId,
			UserId: userId,
			Token:  fmt.Sprintf("%s_sometokenvalue", iAuthTokenId),
		}

		assert.NoError(t, r.AddToken(ctx, addr, iTokenName, iKeyringType, iAuthTokenId))
		p := &Token{
			KeyringType: iKeyringType,
			TokenName:   iTokenName,
			UserId:      userId,
			AuthTokenId: iAuthTokenId,
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
	lp, err := r.listTokens(ctx, &user{
		Id:      userId,
		Address: addr,
	})
	assert.NoError(t, err)
	assert.Len(t, lp, tokensLimit*2/3)
}
