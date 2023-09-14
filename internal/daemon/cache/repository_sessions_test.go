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
	require.NoError(t, r.AddToken(ctx, addr, tokenName, keyringType, at.Id))

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
		u             *user
		sess          []*sessions.Session
		wantCount     int
		errorContains string
	}{
		{
			name: "Success",
			u: &user{
				Address: addr,
				Id:      at.UserId,
			},
			sess:      ss,
			wantCount: len(ss),
		},
		{
			name: "repeated session with different values",
			u: &user{
				Address: addr,
				Id:      at.UserId,
			},
			sess: append(ss, &sessions.Session{
				Id:     ss[0].Id,
				Status: "a different status",
			}),
			wantCount: len(ss),
		},
		{
			name:          "nil user",
			u:             nil,
			sess:          ss,
			errorContains: "user is nil",
		},
		{
			name: "missing user Id",
			u: &user{
				Address: addr,
			},
			sess:          ss,
			errorContains: "user id is missing",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := r.refreshSessions(ctx, tc.u, tc.sess)
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
		p           *Token
		errContains string
	}{
		{
			name:        "nil token",
			p:           nil,
			errContains: "token is nil",
		},
		{
			name: "user id is missing",
			p: &Token{
				TokenName:   "token",
				KeyringType: "keyring",
			},
			errContains: "user id is missing",
		},
		{
			name: "token name is missing",
			p: &Token{
				KeyringType: "keyring",
				UserId:      "user",
			},
			errContains: "token name is missing",
		},
		{
			name: "keyring type is missing",
			p: &Token{
				TokenName: "token",
				UserId:    "user",
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
	t1 := &Token{
		TokenName:   tokenName,
		KeyringType: keyringType,
		UserId:      at.UserId,
		AuthTokenId: at.Id,
	}
	require.NoError(t, r.AddToken(ctx, addr, t1.TokenName, t1.KeyringType, t1.AuthTokenId))

	t2 := t1.clone()
	t2.TokenName = "token2"
	at2 := testAuthTokenLookup(t2.KeyringType, t2.TokenName)
	t2.AuthTokenId = at2.Id
	t2.UserId = at2.UserId
	require.NoError(t, r.AddToken(ctx, addr, t2.TokenName, t2.KeyringType, t2.AuthTokenId))

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
	require.NoError(t, r.refreshSessions(ctx, &user{Address: addr, Id: at.UserId}, ss))

	t.Run("wrong user gets no sessions", func(t *testing.T) {
		l, err := r.ListSessions(ctx, t2)
		assert.NoError(t, err)
		assert.Empty(t, l)
	})
	t.Run("correct token gets sessions", func(t *testing.T) {
		l, err := r.ListSessions(ctx, t1)
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
		t           *Token
		query       string
		errContains string
	}{
		{
			name:        "nil token",
			t:           nil,
			query:       query,
			errContains: "token is nil",
		},
		{
			name: "user id is missing",
			t: &Token{
				TokenName:   "token",
				KeyringType: "keyring",
			},
			query:       query,
			errContains: "user id is missing",
		},
		{
			name: "token name is missing",
			t: &Token{
				KeyringType: "keyring",
				UserId:      "user",
			},
			query:       query,
			errContains: "token name is missing",
		},
		{
			name: "keyring type is missing",
			t: &Token{
				TokenName: "token",
				UserId:    "user",
			},
			query:       query,
			errContains: "keyring type is missing",
		},
		{
			name: "query is missing",
			t: &Token{
				TokenName:   "token",
				KeyringType: "keyring",
				UserId:      "user",
			},
			errContains: "query is missing",
		},
	}

	for _, tc := range errorCases {
		t.Run(tc.name, func(t *testing.T) {
			l, err := r.QuerySessions(ctx, tc.t, tc.query)
			assert.Nil(t, l)
			assert.ErrorContains(t, err, tc.errContains)
		})
	}

	addr := "address"
	keyringType := "keyring"
	tokenName := "token"
	at := testAuthTokenLookup(keyringType, tokenName)
	p1 := &Token{
		TokenName:   tokenName,
		KeyringType: keyringType,
		UserId:      at.UserId,
		AuthTokenId: at.Id,
	}
	require.NoError(t, r.AddToken(ctx, addr, p1.TokenName, p1.KeyringType, p1.AuthTokenId))

	p2 := p1.clone()
	p2.TokenName = "token2"
	at2 := testAuthTokenLookup(p2.KeyringType, p2.TokenName)
	p2.AuthTokenId = at2.Id
	p2.UserId = at2.UserId
	require.NoError(t, r.AddToken(ctx, addr, p2.TokenName, p2.KeyringType, p2.AuthTokenId))

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
	require.NoError(t, r.refreshSessions(ctx, &user{Id: at.UserId, Address: addr}, ss))

	t.Run("wrong token gets no sessions", func(t *testing.T) {
		l, err := r.QuerySessions(ctx, p2, query)
		assert.NoError(t, err)
		assert.Empty(t, l)
	})
	t.Run("correct token gets sessions", func(t *testing.T) {
		l, err := r.QuerySessions(ctx, p1, query)
		assert.NoError(t, err)
		assert.Len(t, l, 2)
		assert.ElementsMatch(t, l, ss[0:2])
	})
}
