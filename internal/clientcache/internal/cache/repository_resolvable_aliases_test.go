// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"encoding/json"
	"strconv"
	"sync"
	"testing"

	"github.com/hashicorp/boundary/api/aliases"
	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/api/targets"
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
	var want []*ResolvableAlias
	for _, al := range als {
		si, err := json.Marshal(al)
		require.NoError(t, err)
		want = append(want, &ResolvableAlias{
			FkUserId:      u.Id,
			Id:            al.Id,
			Type:          al.Type,
			DestinationId: al.DestinationId,
			Value:         al.Value,
			Item:          string(si),
		})
	}
	cases := []struct {
		name          string
		u             *user
		al            []*aliases.Alias
		want          []*ResolvableAlias
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
			want: append(want[1:], &ResolvableAlias{
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
			err := r.refreshResolvableAliases(ctx, tc.u, map[AuthToken]string{{Id: "id"}: "something"},
				WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testStaticResourceRetrievalFuncForId(t, [][]*aliases.Alias{tc.al}, [][]string{nil}))))
			if tc.errorContains == "" {
				assert.NoError(t, err)
				rw := db.New(s)
				var got []*ResolvableAlias
				require.NoError(t, rw.SearchWhere(ctx, &got, "true", nil))
				assert.ElementsMatch(t, got, tc.want)

				t.Cleanup(func() {
					refTok := &refreshToken{
						UserId:       tc.u.Id,
						ResourceType: resolvableAliasResourceType,
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

	err = r.refreshResolvableAliases(ctx, &u, map[AuthToken]string{{Id: "id"}: "something"},
		WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testStaticResourceRetrievalFuncForId(t, ss, [][]string{nil, nil}))))
	assert.NoError(t, err)

	got, err := r.ListResolvableAliases(ctx, at.Id)
	require.NoError(t, err)
	assert.Len(t, got.ResolvableAliases, 2)

	// Refreshing again uses the refresh token and get additional aliases, appending
	// them to the response
	err = r.refreshResolvableAliases(ctx, &u, map[AuthToken]string{{Id: "id"}: "something"},
		WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testStaticResourceRetrievalFuncForId(t, ss, [][]string{nil, nil}))))
	assert.NoError(t, err)

	got, err = r.ListResolvableAliases(ctx, at.Id)
	require.NoError(t, err)
	assert.Len(t, got.ResolvableAliases, 3)

	// Refreshing again wont return any more resources, but also none should be
	// removed
	require.NoError(t, r.refreshResolvableAliases(ctx, &u, map[AuthToken]string{{Id: "id"}: "something"},
		WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testStaticResourceRetrievalFuncForId(t, ss, [][]string{nil, nil})))))
	assert.NoError(t, err)

	got, err = r.ListResolvableAliases(ctx, at.Id)
	require.NoError(t, err)
	assert.Len(t, got.ResolvableAliases, 3)

	// Refresh again with the refresh token being reported as invalid.
	require.NoError(t, r.refreshResolvableAliases(ctx, &u, map[AuthToken]string{{Id: "id"}: "something"},
		WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testErroringForRefreshTokenRetrievalFuncForId(t, ss[0])))))
	assert.NoError(t, err)

	got, err = r.ListResolvableAliases(ctx, at.Id)
	require.NoError(t, err)
	assert.Len(t, got.ResolvableAliases, 2)
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
		l, err := r.ListResolvableAliases(ctx, "")
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
	require.NoError(t, r.refreshResolvableAliases(ctx, u1, map[AuthToken]string{{Id: "id"}: "something"},
		WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testStaticResourceRetrievalFuncForId(t, [][]*aliases.Alias{ss}, [][]string{nil})))))

	t.Run("wrong user gets no aliases", func(t *testing.T) {
		l, err := r.ListResolvableAliases(ctx, kt2.AuthTokenId)
		assert.NoError(t, err)
		assert.Empty(t, l.ResolvableAliases)
	})
	t.Run("correct token gets aliases", func(t *testing.T) {
		l, err := r.ListResolvableAliases(ctx, kt1.AuthTokenId)
		assert.NoError(t, err)
		assert.Len(t, l.ResolvableAliases, len(ss))
		assert.ElementsMatch(t, l.ResolvableAliases, ss)
	})
}

func TestRepository_ListAliasesLimiting(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)

	addr := "address"
	u := &user{
		Id:      "u",
		Address: addr,
	}
	at := &authtokens.AuthToken{
		Id:     "at",
		Token:  "at_token",
		UserId: u.Id,
	}
	kt := KeyringToken{KeyringType: "k", TokenName: "t", AuthTokenId: at.Id}

	atMap := map[ringToken]*authtokens.AuthToken{
		{"k", "t"}: at,
	}
	r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(maps.Values(atMap)))
	require.NoError(t, err)
	require.NoError(t, r.AddKeyringToken(ctx, addr, kt))

	var ts []*aliases.Alias
	for i := 0; i < defaultLimitedResultSetSize*2; i++ {
		ts = append(ts, alias("s"+strconv.Itoa(i)))
	}
	require.NoError(t, r.refreshResolvableAliases(ctx, u, map[AuthToken]string{{Id: "id"}: "something"},
		WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testStaticResourceRetrievalFuncForId(t, [][]*aliases.Alias{ts}, [][]string{nil})))))

	searchService, err := NewSearchService(ctx, r)
	require.NoError(t, err)
	params := SearchParams{
		Resource:    ResolvableAliases,
		AuthTokenId: kt.AuthTokenId,
	}

	t.Run("default limit", func(t *testing.T) {
		searchResult, err := searchService.Search(ctx, params)
		require.NoError(t, err)
		assert.Len(t, searchResult.ResolvableAliases, defaultLimitedResultSetSize)
		assert.True(t, searchResult.Incomplete)
	})
	t.Run("custom limit", func(t *testing.T) {
		params.MaxResultSetSize = 20
		searchResult, err := searchService.Search(ctx, params)
		require.NoError(t, err)
		assert.Len(t, searchResult.ResolvableAliases, params.MaxResultSetSize)
		assert.True(t, searchResult.Incomplete)
	})
	t.Run("no limit", func(t *testing.T) {
		params.MaxResultSetSize = -1
		searchResult, err := searchService.Search(ctx, params)
		require.NoError(t, err)
		assert.Len(t, searchResult.ResolvableAliases, defaultLimitedResultSetSize*2)
		assert.False(t, searchResult.Incomplete)
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
			l, err := r.QueryResolvableAliases(ctx, tc.t, tc.query)
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
	require.NoError(t, r.refreshResolvableAliases(ctx, u1, map[AuthToken]string{{Id: "id"}: "something"},
		WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testStaticResourceRetrievalFuncForId(t, [][]*aliases.Alias{ss}, [][]string{nil})))))

	t.Run("wrong token gets no aliases", func(t *testing.T) {
		l, err := r.QueryResolvableAliases(ctx, kt2.AuthTokenId, query)
		assert.NoError(t, err)
		assert.Empty(t, l.ResolvableAliases)
	})
	t.Run("correct token gets aliases", func(t *testing.T) {
		l, err := r.QueryResolvableAliases(ctx, kt1.AuthTokenId, query)
		assert.NoError(t, err)
		assert.Len(t, l.ResolvableAliases, 2)
		assert.ElementsMatch(t, l.ResolvableAliases, ss[0:2])
	})
}

func TestRepository_QueryResolvableAliasesLimiting(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)

	addr := "address"
	u := &user{
		Id:      "u",
		Address: addr,
	}
	at := &authtokens.AuthToken{
		Id:     "at",
		Token:  "at_token",
		UserId: u.Id,
	}
	kt := KeyringToken{KeyringType: "k", TokenName: "t", AuthTokenId: at.Id}

	atMap := map[ringToken]*authtokens.AuthToken{
		{"k", "t"}: at,
	}
	r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(maps.Values(atMap)))
	require.NoError(t, err)
	require.NoError(t, r.AddKeyringToken(ctx, addr, kt))

	var ts []*aliases.Alias
	for i := 0; i < defaultLimitedResultSetSize*2; i++ {
		ts = append(ts, alias("s"+strconv.Itoa(i)))
	}
	require.NoError(t, r.refreshResolvableAliases(ctx, u, map[AuthToken]string{{Id: "id"}: "something"},
		WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testStaticResourceRetrievalFuncForId(t, [][]*aliases.Alias{ts}, [][]string{nil})))))

	searchService, err := NewSearchService(ctx, r)
	require.NoError(t, err)
	params := SearchParams{
		Resource:    ResolvableAliases,
		AuthTokenId: kt.AuthTokenId,
		Query:       `(type % 'target')`,
	}

	t.Run("default limit", func(t *testing.T) {
		searchResult, err := searchService.Search(ctx, params)
		require.NoError(t, err)
		assert.Len(t, searchResult.ResolvableAliases, defaultLimitedResultSetSize)
		assert.True(t, searchResult.Incomplete)
	})
	t.Run("custom limit", func(t *testing.T) {
		params.MaxResultSetSize = 20
		searchResult, err := searchService.Search(ctx, params)
		require.NoError(t, err)
		assert.Len(t, searchResult.ResolvableAliases, params.MaxResultSetSize)
		assert.True(t, searchResult.Incomplete)
	})
	t.Run("no limit", func(t *testing.T) {
		params.MaxResultSetSize = -1
		searchResult, err := searchService.Search(ctx, params)
		require.NoError(t, err)
		assert.Len(t, searchResult.ResolvableAliases, defaultLimitedResultSetSize*2)
		assert.False(t, searchResult.Incomplete)
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
	tarClient := targets.NewClient(tc.Client())
	tar1, err := tarClient.Create(tc.Context(), "tcp", "p_1234567890", targets.WithName("tar1"), targets.WithTcpTargetDefaultPort(22), targets.WithAliases([]targets.Alias{
		{
			Value:   "val1",
			ScopeId: "global",
		},
	}))
	require.NoError(t, err)
	require.NotNil(t, tar1)

	got, refTok, err := defaultResolvableAliasFunc(tc.Context(), tc.ApiAddrs()[0], tc.Token().Token, tc.Token().UserId, "", nil)
	assert.NoError(t, err)
	assert.NotEmpty(t, refTok)
	assert.Empty(t, got.RemovedIds)
	assert.Len(t, got.Items, 1)

	got2, refTok2, err := defaultResolvableAliasFunc(tc.Context(), tc.ApiAddrs()[0], tc.Token().Token, tc.Token().UserId, refTok, nil)
	assert.NoError(t, err)
	assert.NotEmpty(t, refTok2)
	assert.Empty(t, got2.RemovedIds)
	assert.Empty(t, got2.Items)
}
