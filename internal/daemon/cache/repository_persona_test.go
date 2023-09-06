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

func testAuthTokenLookup(k, t string) *authtokens.AuthToken {
	return &authtokens.AuthToken{
		Id:           fmt.Sprintf("at_%s", t),
		Token:        fmt.Sprintf("at_%s_%s", t, k),
		UserId:       fmt.Sprintf("u_%s", t),
		AuthMethodId: fmt.Sprintf("ampw_%s", t),
		AccountId:    fmt.Sprintf("acctpw_%s", t),
	}
}

func TestRepository_AddPersona(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx)
	require.NoError(t, err)

	r, err := NewRepository(ctx, s, testAuthTokenLookup)
	require.NoError(t, err)

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
			tokenName:     "token",
			keyringType:   "keyring",
			authTokenId:   "authTokenId",
			errorContains: "",
		},
		{
			name:          "missing address",
			tokenName:     "token",
			keyringType:   "keyring",
			authTokenId:   "authTokenId",
			errorContains: "boundary address is empty",
		},
		{
			name:          "missing token",
			addr:          "address",
			keyringType:   "keyring",
			authTokenId:   "authTokenId",
			errorContains: "token name is empty",
		},
		{
			name:          "missing keyring type",
			addr:          "address",
			tokenName:     "token",
			authTokenId:   "authTokenId",
			errorContains: "keyring type is empty",
		},
		{
			name:          "missing auth token id",
			addr:          "address",
			tokenName:     "token",
			keyringType:   "keyring",
			errorContains: "boundary auth token id is empty",
		},
	}

	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			err := r.AddPersona(ctx, tc.addr, tc.tokenName, tc.keyringType, tc.authTokenId)
			assert.ErrorContains(t, err, tc.errorContains)
		})
	}
}

func TestRepository_AddPersona_EvictsOverLimit(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx)
	require.NoError(t, err)

	r, err := NewRepository(ctx, s, testAuthTokenLookup)
	require.NoError(t, err)

	addr := "address"
	keyringType := "keyring"
	tokenName := "token"
	at := testAuthTokenLookup(keyringType, tokenName)

	assert.NoError(t, r.AddPersona(ctx, addr, tokenName, keyringType, at.Id))
	assert.NoError(t, r.AddPersona(ctx, addr, tokenName, keyringType, at.Id))
	for i := 0; i < personaLimit; i++ {
		kr := fmt.Sprintf("%s%d", keyringType, i)
		tn := fmt.Sprintf("%s%d", tokenName, i)
		at := testAuthTokenLookup(kr, tn)
		assert.NoError(t, r.AddPersona(ctx, addr, tn, kr, at.Id))
	}
	// Lookup the first persona added. It should have been evicted for being
	// used the least recently.
	gotP, err := r.LookupPersona(ctx, tokenName, keyringType)
	assert.NoError(t, err)
	assert.Nil(t, gotP)

	gotP, err = r.LookupPersona(ctx, tokenName+"0", keyringType+"0")
	assert.NoError(t, err)
	assert.NotEmpty(t, gotP)
}

func TestRepository_AddPersona_AddingExistingUpdatesLastAccessedTime(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, WithDebug(true))
	require.NoError(t, err)

	r, err := NewRepository(ctx, s, testAuthTokenLookup)
	require.NoError(t, err)

	p1 := &Persona{
		BoundaryAddr: "address",
		TokenName:    "default",
		KeyringType:  "keyring",
	}
	at1 := testAuthTokenLookup(p1.KeyringType, p1.TokenName)
	assert.NoError(t, r.AddPersona(ctx, p1.BoundaryAddr, p1.TokenName, p1.KeyringType,
		at1.Id))
	p2 := &Persona{
		BoundaryAddr: "address2",
		TokenName:    "default2",
		KeyringType:  "keyring",
	}
	at2 := testAuthTokenLookup(p2.KeyringType, p2.TokenName)
	assert.NoError(t, r.AddPersona(ctx, p2.BoundaryAddr, p2.TokenName, p2.KeyringType, at2.Id))

	time.Sleep(10 * time.Millisecond)
	assert.NoError(t, r.AddPersona(ctx, p1.BoundaryAddr, p1.TokenName, p1.KeyringType, at1.Id))

	gotP1, err := r.LookupPersona(ctx, p1.TokenName, p1.KeyringType)
	require.NoError(t, err)
	require.NotNil(t, gotP1)
	gotP2, err := r.LookupPersona(ctx, p2.TokenName, p2.KeyringType)
	require.NoError(t, err)
	require.NotNil(t, gotP2)

	assert.Greater(t, gotP1.LastAccessedTime, gotP2.LastAccessedTime)
}

func TestRepository_ListPersonas(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx)
	require.NoError(t, err)

	r, err := NewRepository(ctx, s, testAuthTokenLookup)
	require.NoError(t, err)

	t.Run("no token", func(t *testing.T) {
		gotP, err := r.listPersonas(ctx)
		assert.NoError(t, err)
		assert.Empty(t, gotP)
	})

	personaCount := 15
	addr := "address"
	keyringType := "keyring"
	tokenName := "token"

	for i := 0; i < personaCount; i++ {
		thisAddr := fmt.Sprintf("%s%d", addr, i)
		thisTokenName := fmt.Sprintf("%s%d", tokenName, i)
		at := testAuthTokenLookup(keyringType, thisTokenName)
		require.NoError(t, r.AddPersona(ctx, thisAddr, thisTokenName, keyringType, at.Id))
	}

	t.Run("many personas", func(t *testing.T) {
		gotP, err := r.listPersonas(ctx)
		assert.NoError(t, err)
		assert.Len(t, gotP, personaCount)
	})
}

func TestRepository_DeletePersona(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx)
	require.NoError(t, err)

	r, err := NewRepository(ctx, s, testAuthTokenLookup)
	require.NoError(t, err)

	t.Run("delete non existing", func(t *testing.T) {
		assert.ErrorContains(t, r.deletePersona(ctx, &Persona{BoundaryAddr: "unknown", KeyringType: "Unknown", TokenName: "Unknown"}), "not found")
	})

	t.Run("delete existing", func(t *testing.T) {
		addr := "address"
		keyringType := "keyring"
		tokenName := "token"
		at := testAuthTokenLookup(keyringType, tokenName)
		assert.NoError(t, r.AddPersona(ctx, addr, tokenName, keyringType, at.Id))
		p, err := r.LookupPersona(ctx, tokenName, keyringType)
		require.NoError(t, err)
		require.NotNil(t, p)

		assert.NoError(t, r.deletePersona(ctx, p))

		got, err := r.LookupPersona(ctx, tokenName, keyringType)
		require.NoError(t, err)
		require.Nil(t, got)
	})
}

func TestRepository_LookupPersona(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx)
	require.NoError(t, err)

	r, err := NewRepository(ctx, s, testAuthTokenLookup)
	require.NoError(t, err)

	t.Run("empty token name", func(t *testing.T) {
		p, err := r.LookupPersona(ctx, "", "keyring")
		assert.ErrorContains(t, err, "token name is empty")
		assert.Nil(t, p)
	})
	t.Run("empty keyring type", func(t *testing.T) {
		p, err := r.LookupPersona(ctx, "token", "")
		assert.ErrorContains(t, err, "keyring type is empty")
		assert.Nil(t, p)
	})
	t.Run("not found", func(t *testing.T) {
		p, err := r.LookupPersona(ctx, "token", "keyring")
		assert.NoError(t, err)
		assert.Nil(t, p)
	})
	t.Run("found", func(t *testing.T) {
		addr := "address"
		keyringType := "keyring"
		tokenName := "token"
		at := testAuthTokenLookup(keyringType, tokenName)

		assert.NoError(t, r.AddPersona(ctx, addr, tokenName, keyringType, at.Id))
		p, err := r.LookupPersona(ctx, tokenName, keyringType)
		assert.NoError(t, err)
		assert.NotEmpty(t, p)
	})
	t.Run("withBoundaryAddress", func(t *testing.T) {
		addr := "address"
		keyringType := "keyring"
		tokenName := "token"
		at := testAuthTokenLookup(keyringType, tokenName)

		assert.NoError(t, r.AddPersona(ctx, addr, tokenName, keyringType, at.Id))
		p, err := r.LookupPersona(ctx, tokenName, keyringType, WithBoundaryAddress(addr))
		assert.NoError(t, err)
		assert.NotEmpty(t, p)

		p, err = r.LookupPersona(ctx, tokenName, keyringType, WithBoundaryAddress("wrong"))
		assert.NoError(t, err)
		assert.Empty(t, p)
	})
	t.Run("withAuthTokenId", func(t *testing.T) {
		addr := "address"
		keyringType := "keyring"
		tokenName := "token"
		at := testAuthTokenLookup(keyringType, tokenName)

		assert.NoError(t, r.AddPersona(ctx, addr, tokenName, keyringType, at.Id))
		p, err := r.LookupPersona(ctx, tokenName, keyringType, WithAuthTokenId(at.Id))
		assert.NoError(t, err)
		assert.NotEmpty(t, p)

		p, err = r.LookupPersona(ctx, tokenName, keyringType, WithAuthTokenId("wrong"))
		assert.NoError(t, err)
		assert.Empty(t, p)
	})
}

func TestRepository_RemoveStalePersonas(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx)
	require.NoError(t, err)

	r, err := NewRepository(ctx, s, testAuthTokenLookup)
	require.NoError(t, err)

	staleTime := time.Now().Add(-(personaStalenessLimit + 1*time.Hour))
	oldNotStaleTime := time.Now().Add(-(personaStalenessLimit - 1*time.Hour))

	addr := "address"
	keyringType := "keyring"
	tokenName := "token"
	for i := 0; i < personaLimit; i++ {
		bAddr := fmt.Sprintf("%s%d", addr, i)
		iTokenName := fmt.Sprintf("%s%d", tokenName, i)
		at := testAuthTokenLookup(keyringType, iTokenName)
		assert.NoError(t, r.AddPersona(ctx, bAddr, iTokenName, keyringType, at.Id))
		p := &Persona{
			KeyringType:  keyringType,
			TokenName:    iTokenName,
			BoundaryAddr: bAddr,
			UserId:       at.UserId,
			AuthTokenId:  at.Id,
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

	assert.NoError(t, r.removeStalePersonas(ctx))
	lp, err := r.listPersonas(ctx)
	assert.NoError(t, err)
	assert.Len(t, lp, personaLimit*2/3)
}
