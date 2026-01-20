// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"encoding/json"
	"strconv"
	"sync"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/globals"
	cachedb "github.com/hashicorp/boundary/internal/clientcache/internal/db"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
)

func TestRepository_refreshTargets(t *testing.T) {
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
	kt := KeyringToken{KeyringType: "k", TokenName: "t", AuthTokenId: at.Id}
	atMap := map[ringToken]*authtokens.AuthToken{
		{"k", "t"}: at,
	}
	r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(maps.Values(atMap)))
	require.NoError(t, err)
	require.NoError(t, r.AddKeyringToken(ctx, addr, kt))

	ts := []*targets.Target{
		{
			Id:                "ttcp_1",
			Name:              "name1",
			Description:       "description1",
			Type:              "tcp",
			ScopeId:           "p_123",
			SessionMaxSeconds: 111,
		},
		{
			Id:                "ttcp_2",
			Name:              "name2",
			Address:           "address2",
			Type:              "tcp",
			ScopeId:           "p_123",
			SessionMaxSeconds: 222,
		},
		{
			Id:                "ttcp_3",
			Name:              "name3",
			Address:           "address3",
			Type:              "tcp",
			ScopeId:           "p_123",
			SessionMaxSeconds: 333,
		},
	}
	var want []*Target
	for _, tar := range ts {
		ti, err := json.Marshal(tar)
		require.NoError(t, err)
		want = append(want, &Target{
			FkUserId:    u.Id,
			Id:          tar.Id,
			Name:        tar.Name,
			Description: tar.Description,
			Address:     tar.Address,
			ScopeId:     tar.ScopeId,
			Type:        tar.Type,
			Item:        string(ti),
		})
	}
	cases := []struct {
		name          string
		u             *user
		targets       []*targets.Target
		want          []*Target
		errorContains string
	}{
		{
			name: "Success",
			u: &user{
				Id:      at.UserId,
				Address: addr,
			},
			targets: ts,
			want:    want,
		},
		// this test case must run after the above test case so as to exercise
		// the update logic of refresh.
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
			want: append(want[1:],
				&Target{
					FkUserId: want[0].FkUserId,
					Id:       want[0].Id,
					Name:     "a different name",
					Item:     `{"id":"ttcp_1","name":"a different name","created_time":"0001-01-01T00:00:00Z","updated_time":"0001-01-01T00:00:00Z"}`,
				}),
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
			err := r.refreshTargets(ctx, tc.u, map[AuthToken]string{{Id: "id"}: "something"},
				WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc(t, [][]*targets.Target{tc.targets}, [][]string{nil}))))
			if tc.errorContains == "" {
				assert.NoError(t, err)
				rw := db.New(s)
				var got []*Target
				require.NoError(t, rw.SearchWhere(ctx, &got, "true", nil))
				assert.ElementsMatch(t, got, tc.want)

				t.Cleanup(func() {
					refTok := &refreshToken{
						UserId:       tc.u.Id,
						ResourceType: targetResourceType,
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

func TestRepository_RefreshTargets_InvalidListTokenError(t *testing.T) {
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

	ts := [][]*targets.Target{
		{
			target("1"),
			target("2"),
			target("3"),
		},
	}

	var withRefreshToken int
	var withoutRefreshToken int
	// invalidAuthTokenFunc returns an invalid auth token error if an auth token
	// is provided, otherwise it returns the tokens with a new auth token.
	invalidAuthTokenFunc := func(ctx context.Context, addr, authTok string, refreshTok RefreshTokenValue) (ret []*targets.Target, removedIds []string, refreshToken RefreshTokenValue, err error) {
		if refreshTok != "" {
			withRefreshToken += 1
			return nil, nil, "", api.ErrInvalidListToken
		}
		withoutRefreshToken += 1
		return testStaticResourceRetrievalFunc(t, ts, [][]string{nil})(ctx, addr, authTok, refreshTok)
	}

	require.NoError(t, r.refreshTargets(ctx, &u, map[AuthToken]string{{Id: "id"}: "something"},
		WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(invalidAuthTokenFunc))))

	// This time an invalid auth token should be returned, and refreshTargets should fall back
	// to requesting without one.
	require.NoError(t, r.refreshTargets(ctx, &u, map[AuthToken]string{{Id: "id"}: "something"},
		WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(invalidAuthTokenFunc))))

	assert.Equal(t, 1, withRefreshToken)
	assert.Equal(t, 2, withoutRefreshToken)
}

func TestRepository_RefreshTargets_withRefreshTokens(t *testing.T) {
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

	ts := [][]*targets.Target{
		{
			target("1"),
			target("2"),
		}, {
			target("3"),
		},
	}

	require.NoError(t, r.refreshTargets(ctx, &u, map[AuthToken]string{{Id: "id"}: "something"},
		WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc(t, ts, [][]string{nil, nil})))))

	got, err := r.ListTargets(ctx, at.Id)
	require.NoError(t, err)
	assert.Len(t, got.Targets, 2)

	// Refreshing again uses the refresh token and get additional sessions, appending
	// them to the response
	require.NoError(t, r.refreshTargets(ctx, &u, map[AuthToken]string{{Id: "id"}: "something"},
		WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc(t, ts, [][]string{nil, nil})))))
	assert.NoError(t, err)

	got, err = r.ListTargets(ctx, at.Id)
	require.NoError(t, err)
	assert.Len(t, got.Targets, 3)

	// Refreshing again wont return any more resources, but also none should be
	// removed
	require.NoError(t, r.refreshTargets(ctx, &u, map[AuthToken]string{{Id: "id"}: "something"},
		WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc(t, ts, [][]string{nil, nil})))))
	assert.NoError(t, err)

	got, err = r.ListTargets(ctx, at.Id)
	require.NoError(t, err)
	assert.Len(t, got.Targets, 3)

	// Refresh again with the refresh token being reported as invalid.
	require.NoError(t, r.refreshTargets(ctx, &u, map[AuthToken]string{{Id: "id"}: "something"},
		WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testErroringForRefreshTokenRetrievalFunc(t, ts[0])))))
	assert.NoError(t, err)

	got, err = r.ListTargets(ctx, at.Id)
	require.NoError(t, err)
	assert.Len(t, got.Targets, 2)
}

func TestRepository_ListTargets(t *testing.T) {
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
	kt1 := KeyringToken{KeyringType: "k1", TokenName: "t1", AuthTokenId: at1.Id}

	u2 := &user{
		Id:      "u2",
		Address: addr,
	}
	at2 := &authtokens.AuthToken{
		Id:     "at_2",
		Token:  "at_2_token",
		UserId: u2.Id,
	}
	kt2 := KeyringToken{KeyringType: "k2", TokenName: "t2", AuthTokenId: at2.Id}
	atMap := map[ringToken]*authtokens.AuthToken{
		{"k1", "t1"}: at1,
		{"k2", "t2"}: at2,
	}
	r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(maps.Values(atMap)))
	require.NoError(t, err)
	require.NoError(t, r.AddKeyringToken(ctx, addr, kt1))
	require.NoError(t, r.AddKeyringToken(ctx, addr, kt2))

	t.Run("token is missing", func(t *testing.T) {
		l, err := r.ListTargets(ctx, "")
		assert.Nil(t, l)
		assert.ErrorContains(t, err, "auth token id is missing")
	})

	ts := []*targets.Target{
		target("1"),
		target("2"),
		target("3"),
	}
	require.NoError(t, r.refreshTargets(ctx, u1, map[AuthToken]string{{Id: "id"}: "something"},
		WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc(t, [][]*targets.Target{ts}, [][]string{nil})))))

	t.Run("wrong user gets no targets", func(t *testing.T) {
		l, err := r.ListTargets(ctx, kt2.AuthTokenId)
		assert.NoError(t, err)
		assert.Empty(t, l.Targets)
	})
	t.Run("correct token gets targets", func(t *testing.T) {
		l, err := r.ListTargets(ctx, kt1.AuthTokenId)
		assert.NoError(t, err)
		assert.Len(t, l.Targets, len(ts))
		assert.ElementsMatch(t, l.Targets, ts)
	})

	t.Run("withSortBy sorts targets", func(t *testing.T) {
		l, err := r.ListTargets(ctx, kt1.AuthTokenId, WithSort(SortByName, Descending, []SortBy{SortByName}))
		assert.NoError(t, err)
		assert.Equal(t, ts[2].Name, l.Targets[0].Name)
		assert.Equal(t, ts[1].Name, l.Targets[1].Name)
		assert.Equal(t, ts[0].Name, l.Targets[2].Name)
	})

	t.Run("withSortBy bad SortBy errors", func(t *testing.T) {
		_, err := r.ListTargets(ctx, kt1.AuthTokenId, WithSort(SortByCreatedAt, Descending, []SortBy{SortByName}))
		assert.Error(t, err)
	})

	t.Run("withSortBy bad SortDirection defaults to Ascending", func(t *testing.T) {
		l, err := r.ListTargets(ctx, kt1.AuthTokenId, WithSort(SortByName, "Something else", []SortBy{SortByName}))
		assert.NoError(t, err)
		assert.Equal(t, ts[0].Name, l.Targets[0].Name)
		assert.Equal(t, ts[1].Name, l.Targets[1].Name)
		assert.Equal(t, ts[2].Name, l.Targets[2].Name)
	})
}

func TestRepository_ListTargetsLimiting(t *testing.T) {
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

	var ts []*targets.Target
	for i := 0; i < defaultLimitedResultSetSize*2; i++ {
		ts = append(ts, target("t"+strconv.Itoa(i)))
	}
	require.NoError(t, r.refreshTargets(ctx, u, map[AuthToken]string{{Id: "id"}: "something"},
		WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc(t, [][]*targets.Target{ts}, [][]string{nil})))))

	searchService, err := NewSearchService(ctx, r)
	require.NoError(t, err)
	params := SearchParams{
		Resource:    Targets,
		AuthTokenId: kt.AuthTokenId,
	}

	t.Run("default limit", func(t *testing.T) {
		searchResult, err := searchService.Search(ctx, params)
		require.NoError(t, err)
		assert.Len(t, searchResult.Targets, defaultLimitedResultSetSize)
		assert.True(t, searchResult.Incomplete)
	})
	t.Run("custom limit", func(t *testing.T) {
		params.MaxResultSetSize = 20
		searchResult, err := searchService.Search(ctx, params)
		require.NoError(t, err)
		assert.Len(t, searchResult.Targets, params.MaxResultSetSize)
		assert.True(t, searchResult.Incomplete)
	})
	t.Run("no limit", func(t *testing.T) {
		params.MaxResultSetSize = -1
		searchResult, err := searchService.Search(ctx, params)
		require.NoError(t, err)
		assert.Len(t, searchResult.Targets, defaultLimitedResultSetSize*2)
		assert.False(t, searchResult.Incomplete)
	})
}

func TestRepository_QueryTargets(t *testing.T) {
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
	kt1 := KeyringToken{KeyringType: "k1", TokenName: "t1", AuthTokenId: at1.Id}

	u2 := &user{
		Id:      "u2",
		Address: addr,
	}
	at2 := &authtokens.AuthToken{
		Id:     "at_2",
		Token:  "at_2_token",
		UserId: u2.Id,
	}
	kt2 := KeyringToken{KeyringType: "k2", TokenName: "t2", AuthTokenId: at2.Id}
	atMap := map[ringToken]*authtokens.AuthToken{
		{"k1", "t1"}: at1,
		{"k2", "t2"}: at2,
	}
	r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(maps.Values(atMap)))
	require.NoError(t, err)
	require.NoError(t, r.AddKeyringToken(ctx, addr, kt1))
	require.NoError(t, r.AddKeyringToken(ctx, addr, kt2))

	query := `(name % 'name1' or name % 'name2') and scope_id = "p_123"`

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

	ts := []*targets.Target{
		{
			Id:                "ttcp_1",
			Name:              "name1",
			Address:           "address1",
			Type:              "tcp",
			ScopeId:           "p_123",
			SessionMaxSeconds: 111,
		},
		{
			Id:                "ttcp_2",
			Name:              "name2",
			Address:           "address2",
			Type:              "tcp",
			ScopeId:           "p_123",
			SessionMaxSeconds: 222,
		},
		{
			Id:                "ttcp_3",
			Name:              "name3",
			Address:           "address3",
			Type:              "tcp",
			ScopeId:           "p_123",
			SessionMaxSeconds: 333,
		},
	}
	require.NoError(t, r.refreshTargets(ctx, u1, map[AuthToken]string{{Id: "id"}: "something"},
		WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc(t, [][]*targets.Target{ts}, [][]string{nil})))))

	t.Run("wrong token gets no targets", func(t *testing.T) {
		l, err := r.QueryTargets(ctx, kt2.AuthTokenId, query)
		assert.NoError(t, err)
		assert.Empty(t, l.Targets)
	})
	t.Run("correct token gets targets", func(t *testing.T) {
		l, err := r.QueryTargets(ctx, kt1.AuthTokenId, query)
		assert.NoError(t, err)
		assert.Len(t, l.Targets, 2)
		assert.ElementsMatch(t, l.Targets, ts[0:2])
	})

	t.Run("withSortBy sorts targets", func(t *testing.T) {
		l, err := r.QueryTargets(ctx, kt1.AuthTokenId, query, WithSort(SortByName, Descending, []SortBy{SortByName}))
		assert.NoError(t, err)
		assert.Equal(t, ts[1].Name, l.Targets[0].Name)
		assert.Equal(t, ts[0].Name, l.Targets[1].Name)
	})

	t.Run("withSortBy bad SortBy errors", func(t *testing.T) {
		_, err := r.QueryTargets(ctx, kt1.AuthTokenId, query, WithSort(SortByCreatedAt, Descending, []SortBy{SortByName}))
		assert.Error(t, err)
	})

	t.Run("withSortBy bad SortDirection defaults to Ascending", func(t *testing.T) {
		l, err := r.QueryTargets(ctx, kt1.AuthTokenId, query, WithSort(SortByName, "Something else", []SortBy{SortByName}))
		assert.NoError(t, err)
		assert.Equal(t, ts[0].Name, l.Targets[0].Name)
		assert.Equal(t, ts[1].Name, l.Targets[1].Name)
	})
}

func TestRepository_QueryTargetsLimiting(t *testing.T) {
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

	var ts []*targets.Target
	for i := 0; i < defaultLimitedResultSetSize*2; i++ {
		ts = append(ts, target("t"+strconv.Itoa(i)))
	}
	require.NoError(t, r.refreshTargets(ctx, u, map[AuthToken]string{{Id: "id"}: "something"},
		WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc(t, [][]*targets.Target{ts}, [][]string{nil})))))

	searchService, err := NewSearchService(ctx, r)
	require.NoError(t, err)
	params := SearchParams{
		Resource:    Targets,
		AuthTokenId: kt.AuthTokenId,
		Query:       `(name % 'name')`,
	}

	t.Run("default limit", func(t *testing.T) {
		searchResult, err := searchService.Search(ctx, params)
		require.NoError(t, err)
		assert.Len(t, searchResult.Targets, defaultLimitedResultSetSize)
		assert.True(t, searchResult.Incomplete)
	})
	t.Run("custom limit", func(t *testing.T) {
		params.MaxResultSetSize = 20
		searchResult, err := searchService.Search(ctx, params)
		require.NoError(t, err)
		assert.Len(t, searchResult.Targets, params.MaxResultSetSize)
		assert.True(t, searchResult.Incomplete)
	})
	t.Run("no limit", func(t *testing.T) {
		params.MaxResultSetSize = -1
		searchResult, err := searchService.Search(ctx, params)
		require.NoError(t, err)
		assert.Len(t, searchResult.Targets, defaultLimitedResultSetSize*2)
		assert.False(t, searchResult.Incomplete)
	})
}

func TestDefaultTargetRetrievalFunc(t *testing.T) {
	oldDur := globals.RefreshReadLookbackDuration
	globals.RefreshReadLookbackDuration = 0
	t.Cleanup(func() {
		globals.RefreshReadLookbackDuration = oldDur
	})

	tc := controller.NewTestController(t, nil)
	tc.Client().SetToken(tc.Token().Token)
	tarClient := targets.NewClient(tc.Client())

	tar1, err := tarClient.Create(tc.Context(), "tcp", "p_1234567890", targets.WithName("tar1"), targets.WithTcpTargetDefaultPort(1))
	require.NoError(t, err)
	require.NotNil(t, tar1)
	tar2, err := tarClient.Create(tc.Context(), "tcp", "p_1234567890", targets.WithName("tar2"), targets.WithTcpTargetDefaultPort(2))
	require.NoError(t, err)
	require.NotNil(t, tar2)

	got, refTok, err := defaultTargetFunc(tc.Context(), tc.ApiAddrs()[0], tc.Token().Token, "", nil)
	assert.NoError(t, err)
	assert.NotEmpty(t, refTok)
	assert.Empty(t, got.RemovedIds)
	found1 := false
	found2 := false
	for _, t := range got.Items {
		if t.Id == tar1.Item.Id {
			found1 = true
		}
		if t.Id == tar2.Item.Id {
			found2 = true
		}
	}
	assert.True(t, found1, "expected to find target %s in list", tar1.Item.Id)
	assert.True(t, found2, "expected to find target %s in list", tar2.Item.Id)

	got2, refTok2, err := defaultTargetFunc(tc.Context(), tc.ApiAddrs()[0], tc.Token().Token, refTok, nil)
	assert.NoError(t, err)
	assert.NotEmpty(t, refTok2)
	assert.NotEqual(t, refTok2, refTok)
	assert.Empty(t, got.RemovedIds)
	assert.Empty(t, got2.Items)
}
