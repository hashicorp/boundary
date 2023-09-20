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
	kt := KeyringToken{KeyringType: "keyring", TokenName: "token"}
	at := testAuthTokenLookup(kt.KeyringType, kt.TokenName)
	kt.AuthTokenId = at.Id
	require.NoError(t, r.AddKeyringToken(ctx, addr, kt))

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

	t.Run("auth token id is missing", func(t *testing.T) {
		l, err := r.ListSessions(ctx, "")
		assert.Nil(t, l)
		assert.ErrorContains(t, err, "auth token id is missing")
	})

	addr := "address"
	t1 := KeyringToken{KeyringType: "keyring", TokenName: "token"}
	at := testAuthTokenLookup(t1.KeyringType, t1.TokenName)
	t1.AuthTokenId = at.Id
	require.NoError(t, r.AddKeyringToken(ctx, addr, t1))

	t2 := KeyringToken{KeyringType: "keyring", TokenName: "token2"}
	at2 := testAuthTokenLookup(t2.KeyringType, t2.TokenName)
	t2.AuthTokenId = at2.Id
	require.NoError(t, r.AddKeyringToken(ctx, addr, t2))

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
		l, err := r.ListSessions(ctx, t2.AuthTokenId)
		assert.NoError(t, err)
		assert.Empty(t, l)
	})
	t.Run("correct token gets sessions", func(t *testing.T) {
		l, err := r.ListSessions(ctx, t1.AuthTokenId)
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
		t           string
		query       string
		errContains string
	}{
		{
			name:        "auth token id is missing",
			t:           "",
			query:       query,
			errContains: "auth token id is missing",
		},
		{
			name:        "query is missing",
			t:           "token id",
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
	kt := KeyringToken{KeyringType: "keyring", TokenName: "token"}
	at := testAuthTokenLookup(kt.KeyringType, kt.TokenName)
	kt.AuthTokenId = at.Id
	require.NoError(t, r.AddKeyringToken(ctx, addr, kt))

	kt2 := KeyringToken{KeyringType: "keyring", TokenName: "token2"}
	at2 := testAuthTokenLookup(kt2.KeyringType, kt2.TokenName)
	kt2.AuthTokenId = at2.Id
	require.NoError(t, r.AddKeyringToken(ctx, addr, kt2))

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
		l, err := r.QuerySessions(ctx, kt2.AuthTokenId, query)
		assert.NoError(t, err)
		assert.Empty(t, l)
	})
	t.Run("correct token gets sessions", func(t *testing.T) {
		l, err := r.QuerySessions(ctx, kt.AuthTokenId, query)
		assert.NoError(t, err)
		assert.Len(t, l, 2)
		assert.ElementsMatch(t, l, ss[0:2])
	})
}
