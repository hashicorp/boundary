// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_refreshTargets(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx)
	require.NoError(t, err)

	r, err := NewRepository(ctx, s, testAuthTokenLookup)
	require.NoError(t, err)

	addr := "address"
	keyringType := "keyring"
	tokenName := "token"
	at := testAuthTokenLookup(keyringType, tokenName)
	require.NoError(t, r.AddPersona(ctx, addr, tokenName, keyringType, at.Id))

	ts := []*targets.Target{
		{
			Id:                "ttcp_1",
			Name:              "name1",
			Address:           "address1",
			Type:              "tcp",
			SessionMaxSeconds: 111,
		},
		{
			Id:                "ttcp_2",
			Name:              "name2",
			Address:           "address2",
			Type:              "tcp",
			SessionMaxSeconds: 222,
		},
		{
			Id:                "ttcp_3",
			Name:              "name3",
			Address:           "address3",
			Type:              "tcp",
			SessionMaxSeconds: 333,
		},
	}
	cases := []struct {
		name          string
		p             *Persona
		targets       []*targets.Target
		wantCount     int
		errorContains string
	}{
		{
			name: "Success",
			p: &Persona{
				KeyringType:  keyringType,
				TokenName:    tokenName,
				BoundaryAddr: addr,
				UserId:       at.UserId,
			},
			targets:   ts,
			wantCount: len(ts),
		},
		{
			name: "repeated target with different values",
			p: &Persona{
				KeyringType:  keyringType,
				TokenName:    tokenName,
				BoundaryAddr: addr,
				UserId:       at.UserId,
			},
			targets: append(ts, &targets.Target{
				Id:   ts[0].Id,
				Name: "a different name",
			}),
			wantCount: len(ts),
		},
		{
			name:          "nil persona",
			p:             nil,
			targets:       ts,
			errorContains: "persona is nil",
		},
		{
			name: "missing user Id",
			p: &Persona{
				KeyringType:  keyringType,
				TokenName:    tokenName,
				BoundaryAddr: addr,
			},
			targets:       ts,
			errorContains: "user id is missing",
		},
		{
			name: "missing boundary address",
			p: &Persona{
				KeyringType: keyringType,
				TokenName:   tokenName,
				UserId:      at.Id,
			},
			targets:       ts,
			errorContains: "boundary address is missing",
		},
		{
			name: "missing keyring type",
			p: &Persona{
				TokenName:    tokenName,
				BoundaryAddr: addr,
				UserId:       at.Id,
			},
			targets:       ts,
			errorContains: "keyring type is missing",
		},
		{
			name: "missing token name",
			p: &Persona{
				KeyringType:  keyringType,
				BoundaryAddr: addr,
				UserId:       at.Id,
			},
			targets:       ts,
			errorContains: "token name is missing",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := r.refreshCachedTargets(ctx, tc.p, tc.targets)
			if tc.errorContains == "" {
				assert.NoError(t, err)
				rw := db.New(s.conn)
				var got []*Target
				require.NoError(t, rw.SearchWhere(ctx, &got, "true", nil))
				assert.Len(t, got, tc.wantCount)
			} else {
				assert.ErrorContains(t, err, tc.errorContains)
			}
		})
	}
}

func TestRepository_ListTargets(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx)
	require.NoError(t, err)

	r, err := NewRepository(ctx, s, testAuthTokenLookup)
	require.NoError(t, err)

	errorCases := []struct {
		name        string
		p           *Persona
		errContains string
	}{
		{
			name:        "nil persona",
			p:           nil,
			errContains: "persona is nil",
		},
		{
			name: "address is missing",
			p: &Persona{
				TokenName:   "token",
				KeyringType: "keyring",
				UserId:      "user",
			},
			errContains: "address is missing",
		},
		{
			name: "user id is missing",
			p: &Persona{
				TokenName:    "token",
				KeyringType:  "keyring",
				BoundaryAddr: "address",
			},
			errContains: "user id is missing",
		},
		{
			name: "token name is missing",
			p: &Persona{
				KeyringType:  "keyring",
				BoundaryAddr: "address",
				UserId:       "user",
			},
			errContains: "token name is missing",
		},
		{
			name: "keyring type is missing",
			p: &Persona{
				TokenName:    "token",
				BoundaryAddr: "address",
				UserId:       "user",
			},
			errContains: "keyring type is missing",
		},
	}

	for _, tc := range errorCases {
		t.Run(tc.name, func(t *testing.T) {
			l, err := r.ListTargets(ctx, tc.p)
			assert.Nil(t, l)
			assert.ErrorContains(t, err, tc.errContains)
		})
	}

	addr := "address"
	keyringType := "keyring"
	tokenName := "token"
	at := testAuthTokenLookup(keyringType, tokenName)
	p1 := &Persona{
		TokenName:    tokenName,
		KeyringType:  keyringType,
		BoundaryAddr: addr,
		UserId:       at.UserId,
		AuthTokenId:  at.Id,
	}
	require.NoError(t, r.AddPersona(ctx, p1.BoundaryAddr, p1.TokenName, p1.KeyringType, p1.AuthTokenId))

	p2 := p1.clone()
	p2.BoundaryAddr = "address2"
	p2.TokenName = "token2"
	at2 := testAuthTokenLookup(p2.KeyringType, p2.TokenName)
	p2.AuthTokenId = at2.Id
	p2.UserId = at2.UserId
	require.NoError(t, r.AddPersona(ctx, p2.BoundaryAddr, p2.TokenName, p2.KeyringType, p2.AuthTokenId))

	ts := []*targets.Target{
		{
			Id:                "ttcp_1",
			Name:              "name1",
			Address:           "address1",
			Type:              "tcp",
			SessionMaxSeconds: 111,
		},
		{
			Id:                "ttcp_2",
			Name:              "name2",
			Address:           "address2",
			Type:              "tcp",
			SessionMaxSeconds: 222,
		},
		{
			Id:                "ttcp_3",
			Name:              "name3",
			Address:           "address3",
			Type:              "tcp",
			SessionMaxSeconds: 333,
		},
	}
	require.NoError(t, r.refreshCachedTargets(ctx, &Persona{KeyringType: keyringType, TokenName: tokenName, BoundaryAddr: addr, UserId: at.UserId}, ts))

	t.Run("wrong user gets no targets", func(t *testing.T) {
		l, err := r.ListTargets(ctx, p2)
		assert.NoError(t, err)
		assert.Empty(t, l)
	})
	t.Run("correct persona gets targets", func(t *testing.T) {
		l, err := r.ListTargets(ctx, p1)
		assert.NoError(t, err)
		assert.Len(t, l, len(ts))
		assert.ElementsMatch(t, l, ts)
	})
}

func TestRepository_QueryTargets(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx)
	require.NoError(t, err)

	r, err := NewRepository(ctx, s, testAuthTokenLookup)
	require.NoError(t, err)

	query := "name % name1 or name % name2"

	errorCases := []struct {
		name        string
		p           *Persona
		query       string
		errContains string
	}{
		{
			name:        "nil persona",
			p:           nil,
			query:       query,
			errContains: "persona is nil",
		},
		{
			name: "address is missing",
			p: &Persona{
				TokenName:   "token",
				KeyringType: "keyring",
				UserId:      "user",
			},
			query:       query,
			errContains: "address is missing",
		},
		{
			name: "user id is missing",
			p: &Persona{
				TokenName:    "token",
				KeyringType:  "keyring",
				BoundaryAddr: "address",
			},
			query:       query,
			errContains: "user id is missing",
		},
		{
			name: "token name is missing",
			p: &Persona{
				KeyringType:  "keyring",
				BoundaryAddr: "address",
				UserId:       "user",
			},
			query:       query,
			errContains: "token name is missing",
		},
		{
			name: "keyring type is missing",
			p: &Persona{
				TokenName:    "token",
				BoundaryAddr: "address",
				UserId:       "user",
			},
			query:       query,
			errContains: "keyring type is missing",
		},
		{
			name: "query is missing",
			p: &Persona{
				TokenName:    "token",
				KeyringType:  "keyring",
				BoundaryAddr: "address",
				UserId:       "user",
			},
			errContains: "query is missing",
		},
	}

	for _, tc := range errorCases {
		t.Run(tc.name, func(t *testing.T) {
			l, err := r.QueryTargets(ctx, tc.p, tc.query)
			assert.Nil(t, l)
			assert.ErrorContains(t, err, tc.errContains)
		})
	}

	addr := "address"
	keyringType := "keyring"
	tokenName := "token"
	at := testAuthTokenLookup(keyringType, tokenName)
	p1 := &Persona{
		TokenName:    tokenName,
		KeyringType:  keyringType,
		BoundaryAddr: addr,
		UserId:       at.UserId,
		AuthTokenId:  at.Id,
	}
	require.NoError(t, r.AddPersona(ctx, p1.BoundaryAddr, p1.TokenName, p1.KeyringType, p1.AuthTokenId))

	p2 := p1.clone()
	p2.BoundaryAddr = "address2"
	p2.TokenName = "token2"
	at2 := testAuthTokenLookup(p2.KeyringType, p2.TokenName)
	p2.AuthTokenId = at2.Id
	p2.UserId = at2.UserId
	require.NoError(t, r.AddPersona(ctx, p2.BoundaryAddr, p2.TokenName, p2.KeyringType, p2.AuthTokenId))

	ts := []*targets.Target{
		{
			Id:                "ttcp_1",
			Name:              "name1",
			Address:           "address1",
			Type:              "tcp",
			SessionMaxSeconds: 111,
		},
		{
			Id:                "ttcp_2",
			Name:              "name2",
			Address:           "address2",
			Type:              "tcp",
			SessionMaxSeconds: 222,
		},
		{
			Id:                "ttcp_3",
			Name:              "name3",
			Address:           "address3",
			Type:              "tcp",
			SessionMaxSeconds: 333,
		},
	}
	require.NoError(t, r.refreshCachedTargets(ctx, p1, ts))

	t.Run("wrong persona gets no targets", func(t *testing.T) {
		l, err := r.QueryTargets(ctx, p2, query)
		assert.NoError(t, err)
		assert.Empty(t, l)
	})
	t.Run("correct persona gets targets", func(t *testing.T) {
		l, err := r.QueryTargets(ctx, p1, query)
		assert.NoError(t, err)
		assert.Len(t, l, 2)
		assert.ElementsMatch(t, l, ts[0:2])
	})
}

func TestRepository_SaveError(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx)
	require.NoError(t, err)

	r, err := NewRepository(ctx, s, testAuthTokenLookup)
	require.NoError(t, err)

	testResource := "test_resource_type"
	testErr := fmt.Errorf("test error for %q", testResource)

	t.Run("empty resource type", func(t *testing.T) {
		assert.ErrorContains(t, r.SaveError(ctx, "", testErr), "resource type is empty")
	})
	t.Run("nil error", func(t *testing.T) {
		assert.ErrorContains(t, r.SaveError(ctx, testResource, nil), "error is nil")
	})
	t.Run("success", func(t *testing.T) {
		assert.NoError(t, r.SaveError(ctx, testResource, testErr))
	})

	assert.NoError(t, r.SaveError(ctx, testResource, testErr))
}
