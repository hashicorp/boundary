// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/hashicorp/boundary/api/aliases"
	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/globals"
	cachedb "github.com/hashicorp/boundary/internal/clientcache/internal/db"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"

	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/targets/tcp"
)

func TestRepository_refreshAliases(t *testing.T) {
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
	kt := KeyringToken{
		KeyringType: "keyring",
		TokenName:   "token",
		AuthTokenId: at.Id,
	}
	atMap := map[ringToken]*authtokens.AuthToken{
		{kt.KeyringType, kt.TokenName}: at,
	}
	r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(maps.Values(atMap)))
	require.NoError(t, err)
	require.NoError(t, r.AddKeyringToken(ctx, addr, kt))

	als := []*aliases.Alias{
		{
			Id:            "alt_1",
			ScopeId:       "p_123",
			DestinationId: "ttcp_123",
			Value:         "example",
			Type:          "target",
		},
		{
			Id:            "alt_2",
			ScopeId:       "p_123",
			DestinationId: "ttcp_123",
			Value:         "example2",
			Type:          "target",
		},
		{
			Id:            "alt_3",
			ScopeId:       "global",
			DestinationId: "ttcp_123",
			Value:         "example3",
			Type:          "target",
		},
	}
	var want []*Alias
	for _, al := range als {
		si, err := json.Marshal(al)
		require.NoError(t, err)
		want = append(want, &Alias{
			FkUserId:      u.Id,
			Id:            al.Id,
			Type:          al.Type,
			ScopeId:       al.ScopeId,
			DestinationId: al.DestinationId,
			Value:         al.Value,
			Item:          string(si),
		})
	}
	cases := []struct {
		name          string
		u             *user
		al            []*aliases.Alias
		want          []*Alias
		errorContains string
	}{
		{
			name: "Success",
			u: &user{
				Address: addr,
				Id:      at.UserId,
			},
			al:   als,
			want: want,
		},
		{
			name: "repeated alias with different values",
			u: &user{
				Address: addr,
				Id:      at.UserId,
			},
			al: append(als, &aliases.Alias{
				Id:    als[0].Id,
				Value: "different.value",
			}),
			want: append(want[1:], &Alias{
				FkUserId: want[0].FkUserId,
				Id:       want[0].Id,
				Value:    "different.value",
				Item:     `{"id":"alt_1","created_time":"0001-01-01T00:00:00Z","updated_time":"0001-01-01T00:00:00Z","value":"different.value"}`,
			}),
		},
		{
			name:          "nil user",
			u:             nil,
			al:            als,
			errorContains: "user is nil",
		},
		{
			name: "missing user Id",
			u: &user{
				Address: addr,
			},
			al:            als,
			errorContains: "user id is missing",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := r.refreshAliases(ctx, tc.u, map[AuthToken]string{{Id: "id"}: "something"},
				WithAliasRetrievalFunc(testStaticResourceRetrievalFunc(t, [][]*aliases.Alias{tc.al}, [][]string{nil})))
			if tc.errorContains == "" {
				assert.NoError(t, err)
				rw := db.New(s)
				var got []*Alias
				require.NoError(t, rw.SearchWhere(ctx, &got, "true", nil))
				assert.ElementsMatch(t, got, tc.want)

				t.Cleanup(func() {
					refTok := &refreshToken{
						UserId:       tc.u.Id,
						ResourceType: aliasResourceType,
					}
					_, err := r.rw.Delete(ctx, refTok)
					require.NoError(t, err)
				})
			} else {
				assert.ErrorContains(t, err, tc.errorContains)
			}
		})
	}
}

func TestRepository_RefreshAliases_withRefreshTokens(t *testing.T) {
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
	kt := KeyringToken{
		KeyringType: "keyring",
		TokenName:   "token",
		AuthTokenId: at.Id,
	}
	atMap := map[ringToken]*authtokens.AuthToken{
		{kt.KeyringType, kt.TokenName}: at,
	}
	r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(maps.Values(atMap)))
	require.NoError(t, err)
	require.NoError(t, r.AddKeyringToken(ctx, addr, kt))

	ss := [][]*aliases.Alias{
		{
			{
				Id:            "alt_1",
				ScopeId:       "p_123",
				DestinationId: "ttcp_123",
				Value:         "u_123",
				Type:          "tcp",
			},
			{
				Id:            "alt_2",
				ScopeId:       "p_123",
				DestinationId: "ttcp_123",
				Value:         "u_123",
				Type:          "tcp",
			},
		},
		{
			{
				Id:            "alt_3",
				ScopeId:       "p_123",
				DestinationId: "ttcp_123",
				Value:         "u_123",
				Type:          "tcp",
			},
		},
	}

	err = r.refreshAliases(ctx, &u, map[AuthToken]string{{Id: "id"}: "something"},
		WithAliasRetrievalFunc(testStaticResourceRetrievalFunc(t, ss, [][]string{nil, nil})))
	assert.NoError(t, err)

	got, err := r.ListAliases(ctx, at.Id)
	require.NoError(t, err)
	assert.Len(t, got, 2)

	// Refreshing again uses the refresh token and get additional aliases, appending
	// them to the response
	err = r.refreshAliases(ctx, &u, map[AuthToken]string{{Id: "id"}: "something"},
		WithAliasRetrievalFunc(testStaticResourceRetrievalFunc(t, ss, [][]string{nil, nil})))
	assert.NoError(t, err)

	got, err = r.ListAliases(ctx, at.Id)
	require.NoError(t, err)
	assert.Len(t, got, 3)

	// Refreshing again wont return any more resources, but also none should be
	// removed
	require.NoError(t, r.refreshAliases(ctx, &u, map[AuthToken]string{{Id: "id"}: "something"},
		WithAliasRetrievalFunc(testStaticResourceRetrievalFunc(t, ss, [][]string{nil, nil}))))
	assert.NoError(t, err)

	got, err = r.ListAliases(ctx, at.Id)
	require.NoError(t, err)
	assert.Len(t, got, 3)

	// Refresh again with the refresh token being reported as invalid.
	require.NoError(t, r.refreshAliases(ctx, &u, map[AuthToken]string{{Id: "id"}: "something"},
		WithAliasRetrievalFunc(testErroringForRefreshTokenRetrievalFunc(t, ss[0]))))
	assert.NoError(t, err)

	got, err = r.ListAliases(ctx, at.Id)
	require.NoError(t, err)
	assert.Len(t, got, 2)
}

func TestRepository_ListAliases(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)

	addr := "address"
	u1 := &user{
		Id:      "u1",
		Address: addr,
	}
	at1 := &authtokens.AuthToken{
		Id:     "at_1",
		Token:  "at_1_token",
		UserId: u1.Id,
	}
	kt1 := KeyringToken{
		KeyringType: "k1",
		TokenName:   "t1",
		AuthTokenId: at1.Id,
	}
	u2 := &user{
		Id:      "u2",
		Address: addr,
	}
	at2 := &authtokens.AuthToken{
		Id:     "at_2",
		Token:  "at_2_token",
		UserId: u2.Id,
	}
	kt2 := KeyringToken{
		KeyringType: "k2",
		TokenName:   "t2",
		AuthTokenId: at2.Id,
	}
	atMap := map[ringToken]*authtokens.AuthToken{
		{"k1", "t1"}: at1,
		{"k2", "t2"}: at2,
	}
	r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(maps.Values(atMap)))
	require.NoError(t, err)
	require.NoError(t, r.AddKeyringToken(ctx, addr, kt1))
	require.NoError(t, r.AddKeyringToken(ctx, addr, kt2))

	t.Run("auth token id is missing", func(t *testing.T) {
		l, err := r.ListAliases(ctx, "")
		assert.Nil(t, l)
		assert.ErrorContains(t, err, "auth token id is missing")
	})

	ss := []*aliases.Alias{
		{
			Id:            "alt_1",
			ScopeId:       "p_123",
			DestinationId: "ttcp_123",
			Value:         "u_123",
			Type:          "tcp",
		},
		{
			Id:            "alt_2",
			ScopeId:       "o_123",
			DestinationId: "ttcp_123",
			Value:         "u_123",
			Type:          "tcp",
		},
		{
			Id:            "alt_3",
			ScopeId:       "global",
			DestinationId: "ttcp_123",
			Value:         "u_123",
			Type:          "tcp",
		},
	}
	require.NoError(t, r.refreshAliases(ctx, u1, map[AuthToken]string{{Id: "id"}: "something"},
		WithAliasRetrievalFunc(testStaticResourceRetrievalFunc(t, [][]*aliases.Alias{ss}, [][]string{nil}))))

	t.Run("wrong user gets no aliases", func(t *testing.T) {
		l, err := r.ListAliases(ctx, kt2.AuthTokenId)
		assert.NoError(t, err)
		assert.Empty(t, l)
	})
	t.Run("correct token gets aliases", func(t *testing.T) {
		l, err := r.ListAliases(ctx, kt1.AuthTokenId)
		assert.NoError(t, err)
		assert.Len(t, l, len(ss))
		assert.ElementsMatch(t, l, ss)
	})
}

func TestRepository_QueryAliases(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)

	addr := "address"
	u1 := &user{
		Id:      "u1",
		Address: addr,
	}
	at1 := &authtokens.AuthToken{
		Id:     "at_1",
		Token:  "at_1_token",
		UserId: u1.Id,
	}
	kt1 := KeyringToken{
		KeyringType: "k1",
		TokenName:   "t1",
		AuthTokenId: at1.Id,
	}
	u2 := &user{
		Id:      "u2",
		Address: addr,
	}
	at2 := &authtokens.AuthToken{
		Id:     "at_2",
		Token:  "at_2_token",
		UserId: u2.Id,
	}
	kt2 := KeyringToken{
		KeyringType: "k2",
		TokenName:   "t2",
		AuthTokenId: at2.Id,
	}
	atMap := map[ringToken]*authtokens.AuthToken{
		{"k1", "t1"}: at1,
		{"k2", "t2"}: at2,
	}
	r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(maps.Values(atMap)))
	require.NoError(t, err)
	require.NoError(t, r.AddKeyringToken(ctx, addr, kt1))
	require.NoError(t, r.AddKeyringToken(ctx, addr, kt2))

	query := `(value % "val1" or value % "val2") and destination_id % "ttcp_"`

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
			l, err := r.QueryAliases(ctx, tc.t, tc.query)
			assert.Nil(t, l)
			assert.ErrorContains(t, err, tc.errContains)
		})
	}

	ss := []*aliases.Alias{
		{
			Id:            "alt_1",
			ScopeId:       "p_123",
			DestinationId: "ttcp_123",
			Value:         "val1",
			Type:          "target",
		},
		{
			Id:            "alt_2",
			ScopeId:       "p_123",
			DestinationId: "ttcp_123",
			Value:         "val2",
			Type:          "target",
		},
		{
			Id:            "alt_3",
			ScopeId:       "p_123",
			DestinationId: "ttcp_123",
			Value:         "val3",
			Type:          "target",
		},
	}
	require.NoError(t, r.refreshAliases(ctx, u1, map[AuthToken]string{{Id: "id"}: "something"},
		WithAliasRetrievalFunc(testStaticResourceRetrievalFunc(t, [][]*aliases.Alias{ss}, [][]string{nil}))))

	t.Run("wrong token gets no aliases", func(t *testing.T) {
		l, err := r.QueryAliases(ctx, kt2.AuthTokenId, query)
		assert.NoError(t, err)
		assert.Empty(t, l)
	})
	t.Run("correct token gets aliases", func(t *testing.T) {
		l, err := r.QueryAliases(ctx, kt1.AuthTokenId, query)
		assert.NoError(t, err)
		assert.Len(t, l, 2)
		assert.ElementsMatch(t, l, ss[0:2])
	})
}

func TestDefaultAliasRetrievalFunc(t *testing.T) {
	oldDur := globals.RefreshReadLookbackDuration
	globals.RefreshReadLookbackDuration = 0
	t.Cleanup(func() {
		globals.RefreshReadLookbackDuration = oldDur
	})

	tc := controller.NewTestController(t, nil)
	tc.Client().SetToken(tc.Token().Token)
	tarClient := aliases.NewClient(tc.Client())
	al1, err := tarClient.Create(tc.Context(), "target", "global", aliases.WithName("al1"), aliases.WithValue("address"))
	require.NoError(t, err)
	require.NotNil(t, al1)

	got, removed, refTok, err := defaultAliasFunc(tc.Context(), tc.ApiAddrs()[0], tc.Token().Token, "")
	assert.NoError(t, err)
	assert.NotEmpty(t, refTok)
	assert.Empty(t, removed)
	assert.Len(t, got, 1)

	got2, removed2, refTok2, err := defaultAliasFunc(tc.Context(), tc.ApiAddrs()[0], tc.Token().Token, refTok)
	assert.NoError(t, err)
	assert.NotEmpty(t, refTok2)
	assert.Empty(t, removed2)
	assert.Empty(t, got2)
}
