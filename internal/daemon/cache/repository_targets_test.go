// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
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
	kt := KeyringToken{KeyringType: "keyring", TokenName: "token"}
	at := testAuthTokenLookup(keyringType, tokenName)
	kt.AuthTokenId = at.Id
	require.NoError(t, r.AddKeyringToken(ctx, addr, kt))

	ts := []*targets.Target{
		{
			Id:                "ttcp_1",
			Name:              "name1",
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
		u             *user
		targets       []*targets.Target
		wantCount     int
		errorContains string
	}{
		{
			name: "Success",
			u: &user{
				Id:      at.UserId,
				Address: addr,
			},
			targets:   ts,
			wantCount: len(ts),
		},
		{
			name: "repeated target with different values",
			u: &user{
				Address: addr,
				Id:      at.UserId,
			},
			targets: append(ts, &targets.Target{
				Id:   ts[0].Id,
				Name: "a different name",
			}),
			wantCount: len(ts),
		},
		{
			name:          "nil user",
			u:             nil,
			targets:       ts,
			errorContains: "user is nil",
		},
		{
			name: "missing user Id",
			u: &user{
				Address: addr,
			},
			targets:       ts,
			errorContains: "user id is missing",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := r.refreshTargets(ctx, tc.u, tc.targets)
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

	t.Run("token is missing", func(t *testing.T) {
		l, err := r.ListTargets(ctx, "")
		assert.Nil(t, l)
		assert.ErrorContains(t, err, "auth token id is missing")
	})

	addr := "address"
	p1 := KeyringToken{KeyringType: "keyring", TokenName: "token"}
	at := testAuthTokenLookup(p1.KeyringType, p1.TokenName)
	p1.AuthTokenId = at.Id
	require.NoError(t, r.AddKeyringToken(ctx, addr, p1))

	p2 := KeyringToken{KeyringType: "keyring", TokenName: "token2"}
	at2 := testAuthTokenLookup(p2.KeyringType, p2.TokenName)
	p2.AuthTokenId = at2.Id
	require.NoError(t, r.AddKeyringToken(ctx, addr, p2))

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
	require.NoError(t, r.refreshTargets(ctx, &user{Id: at.UserId, Address: addr}, ts))

	t.Run("wrong user gets no targets", func(t *testing.T) {
		l, err := r.ListTargets(ctx, p2.AuthTokenId)
		assert.NoError(t, err)
		assert.Empty(t, l)
	})
	t.Run("correct token gets targets", func(t *testing.T) {
		l, err := r.ListTargets(ctx, p1.AuthTokenId)
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
		p           string
		query       string
		errContains string
	}{
		{
			name:        "auth token id is missing",
			p:           "",
			query:       query,
			errContains: "auth token id is missing",
		},
		{
			name:        "query is missing",
			p:           "authtokenid",
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
	kt := KeyringToken{KeyringType: "keyring", TokenName: "token"}
	at := testAuthTokenLookup(kt.KeyringType, kt.TokenName)
	kt.AuthTokenId = at.Id
	require.NoError(t, r.AddKeyringToken(ctx, addr, kt))

	kt2 := KeyringToken{KeyringType: "keyring", TokenName: "token2"}
	at2 := testAuthTokenLookup(kt2.KeyringType, kt2.TokenName)
	kt2.AuthTokenId = at2.Id
	require.NoError(t, r.AddKeyringToken(ctx, addr, kt2))

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
	require.NoError(t, r.refreshTargets(ctx, &user{Id: at.UserId, Address: addr}, ts))

	t.Run("wrong token gets no targets", func(t *testing.T) {
		l, err := r.QueryTargets(ctx, kt2.AuthTokenId, query)
		assert.NoError(t, err)
		assert.Empty(t, l)
	})
	t.Run("correct token gets targets", func(t *testing.T) {
		l, err := r.QueryTargets(ctx, kt.AuthTokenId, query)
		assert.NoError(t, err)
		assert.Len(t, l, 2)
		assert.ElementsMatch(t, l, ts[0:2])
	})
}
