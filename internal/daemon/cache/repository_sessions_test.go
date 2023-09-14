// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_refreshSessions(t *testing.T) {
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

	ss := []*sessions.Session{
		{
			Id:       "ttcp_1",
			Status:   "status1",
			Endpoint: "address1",
			Type:     "tcp",
		},
		{
			Id:       "ttcp_2",
			Status:   "status2",
			Endpoint: "address2",
			Type:     "tcp",
		},
		{
			Id:       "ttcp_3",
			Status:   "status3",
			Endpoint: "address3",
			Type:     "tcp",
		},
	}
	cases := []struct {
		name          string
		p             *Persona
		sess          []*sessions.Session
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
			sess:      ss,
			wantCount: len(ss),
		},
		{
			name: "repeated session with different values",
			p: &Persona{
				KeyringType:  keyringType,
				TokenName:    tokenName,
				BoundaryAddr: addr,
				UserId:       at.UserId,
			},
			sess: append(ss, &sessions.Session{
				Id:     ss[0].Id,
				Status: "a different status",
			}),
			wantCount: len(ss),
		},
		{
			name:          "nil persona",
			p:             nil,
			sess:          ss,
			errorContains: "persona is nil",
		},
		{
			name: "missing user Id",
			p: &Persona{
				KeyringType:  keyringType,
				TokenName:    tokenName,
				BoundaryAddr: addr,
			},
			sess:          ss,
			errorContains: "user id is missing",
		},
		{
			name: "missing boundary address",
			p: &Persona{
				KeyringType: keyringType,
				TokenName:   tokenName,
				UserId:      at.Id,
			},
			sess:          ss,
			errorContains: "boundary address is missing",
		},
		{
			name: "missing keyring type",
			p: &Persona{
				TokenName:    tokenName,
				BoundaryAddr: addr,
				UserId:       at.Id,
			},
			sess:          ss,
			errorContains: "keyring type is missing",
		},
		{
			name: "missing token name",
			p: &Persona{
				KeyringType:  keyringType,
				BoundaryAddr: addr,
				UserId:       at.Id,
			},
			sess:          ss,
			errorContains: "token name is missing",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := r.refreshCachedSessions(ctx, tc.p, tc.sess)
			if tc.errorContains == "" {
				assert.NoError(t, err)
				rw := db.New(s.conn)
				var got []*Session
				require.NoError(t, rw.SearchWhere(ctx, &got, "true", nil))
				assert.Len(t, got, tc.wantCount)
			} else {
				assert.ErrorContains(t, err, tc.errorContains)
			}
		})
	}
}

func TestRepository_ListSessions(t *testing.T) {
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
			l, err := r.ListSessions(ctx, tc.p)
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

	ss := []*sessions.Session{
		{
			Id:       "ttcp_1",
			Status:   "status1",
			Endpoint: "address1",
			Type:     "tcp",
		},
		{
			Id:       "ttcp_2",
			Status:   "status2",
			Endpoint: "address2",
			Type:     "tcp",
		},
		{
			Id:       "ttcp_3",
			Status:   "status3",
			Endpoint: "address3",
			Type:     "tcp",
		},
	}
	require.NoError(t, r.refreshCachedSessions(ctx, &Persona{KeyringType: keyringType, TokenName: tokenName, BoundaryAddr: addr, UserId: at.UserId}, ss))

	t.Run("wrong user gets no sessions", func(t *testing.T) {
		l, err := r.ListSessions(ctx, p2)
		assert.NoError(t, err)
		assert.Empty(t, l)
	})
	t.Run("correct persona gets sessions", func(t *testing.T) {
		l, err := r.ListSessions(ctx, p1)
		assert.NoError(t, err)
		assert.Len(t, l, len(ss))
		assert.ElementsMatch(t, l, ss)
	})
}

func TestRepository_QuerySessions(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx)
	require.NoError(t, err)

	r, err := NewRepository(ctx, s, testAuthTokenLookup)
	require.NoError(t, err)

	query := "status % status1 or status % status2"

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
			l, err := r.QuerySessions(ctx, tc.p, tc.query)
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

	ss := []*sessions.Session{
		{
			Id:       "ttcp_1",
			Status:   "status1",
			Endpoint: "address1",
			Type:     "tcp",
		},
		{
			Id:       "ttcp_2",
			Status:   "status2",
			Endpoint: "address2",
			Type:     "tcp",
		},
		{
			Id:       "ttcp_3",
			Status:   "status3",
			Endpoint: "address3",
			Type:     "tcp",
		},
	}
	require.NoError(t, r.refreshCachedSessions(ctx, p1, ss))

	t.Run("wrong persona gets no sessions", func(t *testing.T) {
		l, err := r.QuerySessions(ctx, p2, query)
		assert.NoError(t, err)
		assert.Empty(t, l)
	})
	t.Run("correct persona gets sessions", func(t *testing.T) {
		l, err := r.QuerySessions(ctx, p1, query)
		assert.NoError(t, err)
		assert.Len(t, l, 2)
		assert.ElementsMatch(t, l, ss[0:2])
	})
}
