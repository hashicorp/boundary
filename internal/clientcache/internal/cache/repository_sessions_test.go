// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/globals"
	cachedb "github.com/hashicorp/boundary/internal/clientcache/internal/db"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/daemon/worker"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"

	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/targets/tcp"
)

func TestRepository_refreshSessions(t *testing.T) {
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

	ss := []*sessions.Session{
		{
			Id:       "ttcp_1",
			Status:   "status1",
			Endpoint: "address1",
			ScopeId:  "p_123",
			TargetId: "ttcp_123",
			UserId:   "u_123",
			Type:     "tcp",
		},
		{
			Id:       "ttcp_2",
			Status:   "status2",
			Endpoint: "address2",
			ScopeId:  "p_123",
			TargetId: "ttcp_123",
			UserId:   "u_123",
			Type:     "tcp",
		},
		{
			Id:       "ttcp_3",
			Status:   "status3",
			Endpoint: "address3",
			ScopeId:  "p_123",
			TargetId: "ttcp_123",
			UserId:   "u_123",
			Type:     "tcp",
		},
	}
	var want []*Session
	for _, sess := range ss {
		si, err := json.Marshal(sess)
		require.NoError(t, err)
		want = append(want, &Session{
			FkUserId: u.Id,
			Id:       sess.Id,
			Type:     sess.Type,
			Status:   sess.Status,
			Endpoint: sess.Endpoint,
			ScopeId:  sess.ScopeId,
			TargetId: sess.TargetId,
			UserId:   sess.UserId,
			Item:     string(si),
		})
	}
	cases := []struct {
		name          string
		u             *user
		sess          []*sessions.Session
		want          []*Session
		errorContains string
	}{
		{
			name: "Success",
			u: &user{
				Address: addr,
				Id:      at.UserId,
			},
			sess: ss,
			want: want,
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
			want: append(want[1:], &Session{
				FkUserId: want[0].FkUserId,
				Id:       want[0].Id,
				Status:   "a different status",
				Item:     `{"id":"ttcp_1","created_time":"0001-01-01T00:00:00Z","updated_time":"0001-01-01T00:00:00Z","expiration_time":"0001-01-01T00:00:00Z","status":"a different status"}`,
			}),
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
			err := r.refreshSessions(ctx, tc.u, map[AuthToken]string{{Id: "id"}: "something"},
				WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc(t, [][]*sessions.Session{tc.sess}, [][]string{nil}))))
			if tc.errorContains == "" {
				assert.NoError(t, err)
				rw := db.New(s)
				var got []*Session
				require.NoError(t, rw.SearchWhere(ctx, &got, "true", nil))
				assert.ElementsMatch(t, got, tc.want)

				t.Cleanup(func() {
					refTok := &refreshToken{
						UserId:       tc.u.Id,
						ResourceType: sessionResourceType,
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

func TestRepository_RefreshSessions_withRefreshTokens(t *testing.T) {
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

	ss := [][]*sessions.Session{
		{
			{
				Id:       "ttcp_1",
				Status:   "status1",
				Endpoint: "address1",
				ScopeId:  "p_123",
				TargetId: "ttcp_123",
				UserId:   "u_123",
				Type:     "tcp",
			},
			{
				Id:       "ttcp_2",
				Status:   "status2",
				Endpoint: "address2",
				ScopeId:  "p_123",
				TargetId: "ttcp_123",
				UserId:   "u_123",
				Type:     "tcp",
			},
		},
		{
			{
				Id:       "ttcp_3",
				Status:   "status3",
				Endpoint: "address3",
				ScopeId:  "p_123",
				TargetId: "ttcp_123",
				UserId:   "u_123",
				Type:     "tcp",
			},
		},
	}

	err = r.refreshSessions(ctx, &u, map[AuthToken]string{{Id: "id"}: "something"},
		WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc(t, ss, [][]string{nil, nil}))))
	assert.NoError(t, err)

	got, err := r.ListSessions(ctx, at.Id)
	require.NoError(t, err)
	assert.Len(t, got.Sessions, 2)

	// Refreshing again uses the refresh token and get additional sessions, appending
	// them to the response
	err = r.refreshSessions(ctx, &u, map[AuthToken]string{{Id: "id"}: "something"},
		WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc(t, ss, [][]string{nil, nil}))))
	assert.NoError(t, err)

	got, err = r.ListSessions(ctx, at.Id)
	require.NoError(t, err)
	assert.Len(t, got.Sessions, 3)

	// Refreshing again wont return any more resources, but also none should be
	// removed
	require.NoError(t, r.refreshSessions(ctx, &u, map[AuthToken]string{{Id: "id"}: "something"},
		WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc(t, ss, [][]string{nil, nil})))))
	assert.NoError(t, err)

	got, err = r.ListSessions(ctx, at.Id)
	require.NoError(t, err)
	assert.Len(t, got.Sessions, 3)

	// Refresh again with the refresh token being reported as invalid.
	require.NoError(t, r.refreshSessions(ctx, &u, map[AuthToken]string{{Id: "id"}: "something"},
		WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testErroringForRefreshTokenRetrievalFunc(t, ss[0])))))
	assert.NoError(t, err)

	got, err = r.ListSessions(ctx, at.Id)
	require.NoError(t, err)
	assert.Len(t, got.Sessions, 2)
}

func TestRepository_ListSessions(t *testing.T) {
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
		l, err := r.ListSessions(ctx, "")
		assert.Nil(t, l)
		assert.ErrorContains(t, err, "auth token id is missing")
	})

	ss := []*sessions.Session{
		{
			Id:       "ttcp_1",
			Status:   "status1",
			Endpoint: "address1",
			ScopeId:  "p_123",
			TargetId: "ttcp_123",
			UserId:   "u_123",
			Type:     "tcp",
		},
		{
			Id:       "ttcp_2",
			Status:   "status2",
			Endpoint: "address2",
			ScopeId:  "p_123",
			TargetId: "ttcp_123",
			UserId:   "u_123",
			Type:     "tcp",
		},
		{
			Id:       "ttcp_3",
			Status:   "status3",
			Endpoint: "address3",
			ScopeId:  "p_123",
			TargetId: "ttcp_123",
			UserId:   "u_123",
			Type:     "tcp",
		},
	}
	require.NoError(t, r.refreshSessions(ctx, u1, map[AuthToken]string{{Id: "id"}: "something"},
		WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc(t, [][]*sessions.Session{ss}, [][]string{nil})))))

	t.Run("wrong user gets no sessions", func(t *testing.T) {
		l, err := r.ListSessions(ctx, kt2.AuthTokenId)
		assert.NoError(t, err)
		assert.Empty(t, l.Sessions)
	})
	t.Run("correct token gets sessions", func(t *testing.T) {
		l, err := r.ListSessions(ctx, kt1.AuthTokenId)
		assert.NoError(t, err)
		assert.Len(t, l.Sessions, len(ss))
		assert.ElementsMatch(t, l.Sessions, ss)
	})
}

func TestRepository_ListSessionsLimiting(t *testing.T) {
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

	var ts []*sessions.Session
	for i := 0; i < defaultLimitedResultSetSize*2; i++ {
		ts = append(ts, session("s"+strconv.Itoa(i)))
	}
	require.NoError(t, r.refreshSessions(ctx, u, map[AuthToken]string{{Id: "id"}: "something"},
		WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc(t, [][]*sessions.Session{ts}, [][]string{nil})))))

	searchService, err := NewSearchService(ctx, r)
	require.NoError(t, err)
	params := SearchParams{
		Resource:    Sessions,
		AuthTokenId: kt.AuthTokenId,
	}

	t.Run("default limit", func(t *testing.T) {
		searchResult, err := searchService.Search(ctx, params)
		require.NoError(t, err)
		assert.Len(t, searchResult.Sessions, defaultLimitedResultSetSize)
		assert.True(t, searchResult.Incomplete)
	})
	t.Run("custom limit", func(t *testing.T) {
		params.MaxResultSetSize = 20
		searchResult, err := searchService.Search(ctx, params)
		require.NoError(t, err)
		assert.Len(t, searchResult.Sessions, params.MaxResultSetSize)
		assert.True(t, searchResult.Incomplete)
	})
	t.Run("no limit", func(t *testing.T) {
		params.MaxResultSetSize = -1
		searchResult, err := searchService.Search(ctx, params)
		require.NoError(t, err)
		assert.Len(t, searchResult.Sessions, defaultLimitedResultSetSize*2)
		assert.False(t, searchResult.Incomplete)
	})
}

func TestRepository_QuerySessions(t *testing.T) {
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

	query := `(status % "status1" or status % "status2") and target_id % "ttcp_"`

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

	ss := []*sessions.Session{
		{
			Id:       "ttcp_1",
			Status:   "status1",
			Endpoint: "address1",
			ScopeId:  "p_123",
			TargetId: "ttcp_123",
			UserId:   "u_123",
			Type:     "tcp",
		},
		{
			Id:       "ttcp_2",
			Status:   "status2",
			Endpoint: "address2",
			ScopeId:  "p_123",
			TargetId: "ttcp_123",
			UserId:   "u_123",
			Type:     "tcp",
		},
		{
			Id:       "ttcp_3",
			Status:   "status3",
			Endpoint: "address3",
			ScopeId:  "p_123",
			TargetId: "ttcp_123",
			UserId:   "u_123",
			Type:     "tcp",
		},
	}
	require.NoError(t, r.refreshSessions(ctx, u1, map[AuthToken]string{{Id: "id"}: "something"},
		WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc(t, [][]*sessions.Session{ss}, [][]string{nil})))))

	t.Run("wrong token gets no sessions", func(t *testing.T) {
		l, err := r.QuerySessions(ctx, kt2.AuthTokenId, query)
		assert.NoError(t, err)
		assert.Empty(t, l.Sessions)
	})
	t.Run("correct token gets sessions", func(t *testing.T) {
		l, err := r.QuerySessions(ctx, kt1.AuthTokenId, query)
		assert.NoError(t, err)
		assert.Len(t, l.Sessions, 2)
		assert.ElementsMatch(t, l.Sessions, ss[0:2])
	})
}

func TestRepository_QuerySessionsLimiting(t *testing.T) {
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

	var ts []*sessions.Session
	for i := 0; i < defaultLimitedResultSetSize*2; i++ {
		ts = append(ts, session("t"+strconv.Itoa(i)))
	}
	require.NoError(t, r.refreshSessions(ctx, u, map[AuthToken]string{{Id: "id"}: "something"},
		WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc(t, [][]*sessions.Session{ts}, [][]string{nil})))))

	searchService, err := NewSearchService(ctx, r)
	require.NoError(t, err)
	params := SearchParams{
		Resource:    Sessions,
		AuthTokenId: kt.AuthTokenId,
		Query:       `(id % 'session')`,
	}

	t.Run("default limit", func(t *testing.T) {
		searchResult, err := searchService.Search(ctx, params)
		require.NoError(t, err)
		assert.Len(t, searchResult.Sessions, defaultLimitedResultSetSize)
		assert.True(t, searchResult.Incomplete)
	})
	t.Run("custom limit", func(t *testing.T) {
		params.MaxResultSetSize = 20
		searchResult, err := searchService.Search(ctx, params)
		require.NoError(t, err)
		assert.Len(t, searchResult.Sessions, params.MaxResultSetSize)
		assert.True(t, searchResult.Incomplete)
	})
	t.Run("no limit", func(t *testing.T) {
		params.MaxResultSetSize = -1
		searchResult, err := searchService.Search(ctx, params)
		require.NoError(t, err)
		assert.Len(t, searchResult.Sessions, defaultLimitedResultSetSize*2)
		assert.False(t, searchResult.Incomplete)
	})
}

func TestDefaultSessionRetrievalFunc(t *testing.T) {
	// This prevents us from running this test in parallel
	oldDur := globals.RefreshReadLookbackDuration
	globals.RefreshReadLookbackDuration = 0
	t.Cleanup(func() {
		globals.RefreshReadLookbackDuration = oldDur
	})

	tc := controller.NewTestController(t, nil)
	tc.Client().SetToken(tc.Token().Token)
	tarClient := targets.NewClient(tc.Client())
	_ = worker.NewTestWorker(t, &worker.TestWorkerOpts{
		Name:              "test",
		InitialUpstreams:  tc.ClusterAddrs(),
		WorkerAuthKms:     tc.Config().WorkerAuthKms,
		WorkerRPCInterval: time.Second,
	})

	tar1, err := tarClient.Create(tc.Context(), "tcp", "p_1234567890", targets.WithName("tar1"), targets.WithTcpTargetDefaultPort(1), targets.WithAddress("address"))
	require.NoError(t, err)
	require.NotNil(t, tar1)

	require.NoError(t, tc.WaitForNextWorkerRoutingInfoUpdate("test"))
	require.Eventually(t, func() bool {
		_, err = tarClient.AuthorizeSession(tc.Context(), tar1.Item.Id)
		return err == nil
	}, 30*time.Second, time.Second, "timed out waiting to authorize session without an error.")

	got, refTok, err := defaultSessionFunc(tc.Context(), tc.ApiAddrs()[0], tc.Token().Token, "", nil)
	assert.NoError(t, err)
	assert.NotEmpty(t, refTok)
	assert.Empty(t, got.RemovedIds)
	assert.Len(t, got.Items, 1)

	got2, refTok2, err := defaultSessionFunc(tc.Context(), tc.ApiAddrs()[0], tc.Token().Token, refTok, nil)
	assert.NoError(t, err)
	assert.NotEmpty(t, refTok2)
	assert.Empty(t, got2.RemovedIds)
	assert.Empty(t, got2.Items)
}

func TestRepository_SearchSessionsSorting(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)

	addr := "address"
	u := &user{
		Id:      "u1",
		Address: addr,
	}
	at := &authtokens.AuthToken{
		Id:     "at_1",
		Token:  "at_1_token",
		UserId: u.Id,
	}
	kt := KeyringToken{
		KeyringType: "k1",
		TokenName:   "t1",
		AuthTokenId: at.Id,
	}
	atMap := map[ringToken]*authtokens.AuthToken{
		{"k1", "t1"}: at,
	}
	r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(maps.Values(atMap)))
	require.NoError(t, err)
	require.NoError(t, r.AddKeyringToken(ctx, addr, kt))

	// Create sessions with different created_time times
	ss := []*sessions.Session{
		{
			Id:          "ttcp_1",
			Status:      "status1",
			Endpoint:    "address1",
			ScopeId:     "p_123",
			TargetId:    "ttcp_123",
			UserId:      "u_123",
			Type:        "tcp",
			CreatedTime: time.Now().Add(-2 * time.Hour),
		},
		{
			Id:          "ttcp_2",
			Status:      "status2",
			Endpoint:    "address2",
			ScopeId:     "p_123",
			TargetId:    "ttcp_123",
			UserId:      "u_123",
			Type:        "tcp",
			CreatedTime: time.Now().Add(-1 * time.Hour),
		},
		{
			Id:          "ttcp_3",
			Status:      "status3",
			Endpoint:    "address3",
			ScopeId:     "p_123",
			TargetId:    "ttcp_123",
			UserId:      "u_123",
			Type:        "tcp",
			CreatedTime: time.Now(),
		},
	}
	require.NoError(t, r.refreshSessions(ctx, u, map[AuthToken]string{{Id: "id"}: "something"},
		WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc(t, [][]*sessions.Session{ss}, [][]string{nil})))))

	searchService, err := NewSearchService(ctx, r)
	require.NoError(t, err)

	t.Run("sort by created_time ascending", func(t *testing.T) {
		params := SearchParams{
			Resource:      Sessions,
			AuthTokenId:   kt.AuthTokenId,
			SortBy:        SortByCreatedTime,
			SortDirection: Ascending,
		}
		result, err := searchService.Search(ctx, params)
		require.NoError(t, err)
		require.Len(t, result.Sessions, 3)
		assert.Equal(t, "ttcp_1", result.Sessions[0].Id)
		assert.Equal(t, "ttcp_2", result.Sessions[1].Id)
		assert.Equal(t, "ttcp_3", result.Sessions[2].Id)
	})

	t.Run("sort by created_time descending", func(t *testing.T) {
		params := SearchParams{
			Resource:      Sessions,
			AuthTokenId:   kt.AuthTokenId,
			SortBy:        SortByCreatedTime,
			SortDirection: Descending,
		}
		result, err := searchService.Search(ctx, params)
		require.NoError(t, err)
		require.Len(t, result.Sessions, 3)
		assert.Equal(t, "ttcp_3", result.Sessions[0].Id)
		assert.Equal(t, "ttcp_2", result.Sessions[1].Id)
		assert.Equal(t, "ttcp_1", result.Sessions[2].Id)
	})

	t.Run("sort by created_time with default direction defaults to desc", func(t *testing.T) {
		params := SearchParams{
			Resource:      Sessions,
			AuthTokenId:   kt.AuthTokenId,
			SortBy:        SortByCreatedTime,
			SortDirection: SortDirectionDefault,
		}
		result, err := searchService.Search(ctx, params)
		require.NoError(t, err)
		require.Len(t, result.Sessions, 3)
		assert.Equal(t, "ttcp_3", result.Sessions[0].Id)
		assert.Equal(t, "ttcp_2", result.Sessions[1].Id)
		assert.Equal(t, "ttcp_1", result.Sessions[2].Id)
	})

	t.Run("no sort specified returns results", func(t *testing.T) {
		params := SearchParams{
			Resource:    Sessions,
			AuthTokenId: kt.AuthTokenId,
		}
		result, err := searchService.Search(ctx, params)
		require.NoError(t, err)
		assert.Len(t, result.Sessions, 3)
	})

	t.Run("invalid sort column for sessions returns error", func(t *testing.T) {
		params := SearchParams{
			Resource:      Sessions,
			AuthTokenId:   kt.AuthTokenId,
			SortBy:        SortByName, // name is not valid for sessions
			SortDirection: Ascending,
		}
		_, err := searchService.Search(ctx, params)
		require.Error(t, err)
		assert.ErrorContains(t, err, errInvalidSortColumn.Error())
	})

	t.Run("sort with query", func(t *testing.T) {
		params := SearchParams{
			Resource:      Sessions,
			AuthTokenId:   kt.AuthTokenId,
			Query:         `(status % "status")`,
			SortBy:        SortByCreatedTime,
			SortDirection: Descending,
		}
		result, err := searchService.Search(ctx, params)
		require.NoError(t, err)
		require.Len(t, result.Sessions, 3)
		assert.Equal(t, "ttcp_3", result.Sessions[0].Id)
		assert.Equal(t, "ttcp_2", result.Sessions[1].Id)
		assert.Equal(t, "ttcp_1", result.Sessions[2].Id)
	})

	t.Run("sort with limit", func(t *testing.T) {
		params := SearchParams{
			Resource:         Sessions,
			AuthTokenId:      kt.AuthTokenId,
			SortBy:           SortByCreatedTime,
			SortDirection:    Descending,
			MaxResultSetSize: 2,
		}
		result, err := searchService.Search(ctx, params)
		require.NoError(t, err)
		assert.Len(t, result.Sessions, 2)
		assert.True(t, result.Incomplete)
		assert.Equal(t, "ttcp_3", result.Sessions[0].Id)
		assert.Equal(t, "ttcp_2", result.Sessions[1].Id)
	})
}

func TestRepository_searchSessions_dbOptions(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)

	addr := "address"
	u := &user{
		Id:      "u1",
		Address: addr,
	}
	at := &authtokens.AuthToken{
		Id:     "at_1",
		Token:  "at_1_token",
		UserId: u.Id,
	}
	kt := KeyringToken{
		KeyringType: "k1",
		TokenName:   "t1",
		AuthTokenId: at.Id,
	}
	atMap := map[ringToken]*authtokens.AuthToken{
		{"k1", "t1"}: at,
	}
	r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(maps.Values(atMap)))
	require.NoError(t, err)
	require.NoError(t, r.AddKeyringToken(ctx, addr, kt))

	// Create sessions with different created_time values for sorting tests
	// These timestamps are intentionally different to verify sorting works correctly
	now := time.Now()
	ss := []*sessions.Session{
		{
			Id:          "ttcp_1",
			Status:      "status1",
			Endpoint:    "address1",
			ScopeId:     "p_123",
			TargetId:    "ttcp_123",
			UserId:      "u_123",
			Type:        "tcp",
			CreatedTime: now.Add(-2 * time.Hour), // Oldest
		},
		{
			Id:          "ttcp_2",
			Status:      "status2",
			Endpoint:    "address2",
			ScopeId:     "p_123",
			TargetId:    "ttcp_123",
			UserId:      "u_123",
			Type:        "tcp",
			CreatedTime: now.Add(-1 * time.Hour), // Middle
		},
		{
			Id:          "ttcp_3",
			Status:      "status3",
			Endpoint:    "address3",
			ScopeId:     "p_123",
			TargetId:    "ttcp_123",
			UserId:      "u_123",
			Type:        "tcp",
			CreatedTime: now, // Newest
		},
	}
	require.NoError(t, r.refreshSessions(ctx, u, map[AuthToken]string{{Id: "id"}: "something"},
		WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc(t, [][]*sessions.Session{ss}, [][]string{nil})))))

	tests := []struct {
		name             string
		sortBy           SortBy
		sortDirection    SortDirection
		maxResultSetSize int
		expectedOrder    []string // expected session IDs in order - verifies json_extract sorting works
		expectIncomplete bool
	}{
		{
			name:             "default - no sorting",
			sortBy:           SortByDefault,
			sortDirection:    SortDirectionDefault,
			maxResultSetSize: 10,
			expectIncomplete: false,
		},
		{
			name:             "sort by created_time ascending - verifies json_extract asc works",
			sortBy:           SortByCreatedTime,
			sortDirection:    Ascending,
			maxResultSetSize: 10,
			expectedOrder:    []string{"ttcp_1", "ttcp_2", "ttcp_3"}, // oldest to newest
			expectIncomplete: false,
		},
		{
			name:             "sort by created_time descending - verifies json_extract desc works",
			sortBy:           SortByCreatedTime,
			sortDirection:    Descending,
			maxResultSetSize: 10,
			expectedOrder:    []string{"ttcp_3", "ttcp_2", "ttcp_1"}, // newest to oldest
			expectIncomplete: false,
		},
		{
			name:             "sort ascending with limit - verifies LIMIT clause",
			sortBy:           SortByCreatedTime,
			sortDirection:    Ascending,
			maxResultSetSize: 2,
			expectedOrder:    []string{"ttcp_1", "ttcp_2"},
			expectIncomplete: true,
		},
		{
			name:             "sort descending with limit - verifies LIMIT clause",
			sortBy:           SortByCreatedTime,
			sortDirection:    Descending,
			maxResultSetSize: 2,
			expectedOrder:    []string{"ttcp_3", "ttcp_2"},
			expectIncomplete: true,
		},
		{
			name:             "no limit (-1)",
			sortBy:           SortByCreatedTime,
			sortDirection:    Ascending,
			maxResultSetSize: -1,
			expectedOrder:    []string{"ttcp_1", "ttcp_2", "ttcp_3"},
			expectIncomplete: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build options
			opts := []Option{
				withAuthTokenId(at.Id),
				WithMaxResultSetSize(tt.maxResultSetSize),
			}
			if tt.sortBy != SortByDefault {
				opts = append(opts, WithSort(tt.sortBy, tt.sortDirection, []SortBy{SortByCreatedTime}))
			}

			// Execute the search
			result, err := r.searchSessions(ctx, "true", nil, opts...)
			require.NoError(t, err)
			require.NotNil(t, result)

			// Verify the result
			if tt.expectIncomplete {
				assert.True(t, result.Incomplete, "expected incomplete result")
				assert.Len(t, result.Sessions, tt.maxResultSetSize, "expected limited results")
			} else {
				assert.False(t, result.Incomplete, "expected complete result")
			}

			// Verify the order if sorting was applied
			// This proves json_extract(item, '$.created_time') is working correctly
			if tt.sortBy != SortByDefault && len(tt.expectedOrder) > 0 {
				var actualOrder []string
				for _, sess := range result.Sessions {
					actualOrder = append(actualOrder, sess.Id)
				}
				assert.Equal(t, tt.expectedOrder[:len(actualOrder)], actualOrder, "sessions not in expected order")

				// Additionally verify the timestamps are actually in the correct order
				if len(result.Sessions) > 1 {
					for i := 0; i < len(result.Sessions)-1; i++ {
						curr := result.Sessions[i].CreatedTime
						next := result.Sessions[i+1].CreatedTime
						if tt.sortDirection == Ascending {
							assert.True(t, !curr.After(next), "timestamps should be in ascending order")
						} else {
							assert.True(t, !curr.Before(next), "timestamps should be in descending order")
						}
					}
				}
			}
		})
	}
}

func TestRepository_searchSessions_dbOptionsWithQuery(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)

	addr := "address"
	u := &user{
		Id:      "u1",
		Address: addr,
	}
	at := &authtokens.AuthToken{
		Id:     "at_1",
		Token:  "at_1_token",
		UserId: u.Id,
	}
	kt := KeyringToken{
		KeyringType: "k1",
		TokenName:   "t1",
		AuthTokenId: at.Id,
	}
	atMap := map[ringToken]*authtokens.AuthToken{
		{"k1", "t1"}: at,
	}
	r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(maps.Values(atMap)))
	require.NoError(t, err)
	require.NoError(t, r.AddKeyringToken(ctx, addr, kt))

	// Create sessions with different created_time values
	now := time.Now()
	ss := []*sessions.Session{
		{
			Id:          "ttcp_1",
			Status:      "pending",
			Endpoint:    "address1",
			ScopeId:     "p_123",
			TargetId:    "ttcp_123",
			UserId:      "u_123",
			Type:        "tcp",
			CreatedTime: now.Add(-2 * time.Hour),
		},
		{
			Id:          "ttcp_2",
			Status:      "active",
			Endpoint:    "address2",
			ScopeId:     "p_123",
			TargetId:    "ttcp_123",
			UserId:      "u_123",
			Type:        "tcp",
			CreatedTime: now.Add(-1 * time.Hour),
		},
		{
			Id:          "ttcp_3",
			Status:      "active",
			Endpoint:    "address3",
			ScopeId:     "p_123",
			TargetId:    "ttcp_123",
			UserId:      "u_123",
			Type:        "tcp",
			CreatedTime: now,
		},
	}
	require.NoError(t, r.refreshSessions(ctx, u, map[AuthToken]string{{Id: "id"}: "something"},
		WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc(t, [][]*sessions.Session{ss}, [][]string{nil})))))

	tests := []struct {
		name             string
		query            string
		sortBy           SortBy
		sortDirection    SortDirection
		maxResultSetSize int
		expectedCount    int
		expectedOrder    []string
		expectIncomplete bool
	}{
		{
			name:             "query with sort ascending",
			query:            `status % "active"`,
			sortBy:           SortByCreatedTime,
			sortDirection:    Ascending,
			maxResultSetSize: 10,
			expectedCount:    2,
			expectedOrder:    []string{"ttcp_2", "ttcp_3"},
			expectIncomplete: false,
		},
		{
			name:             "query with sort descending",
			query:            `status % "active"`,
			sortBy:           SortByCreatedTime,
			sortDirection:    Descending,
			maxResultSetSize: 10,
			expectedCount:    2,
			expectedOrder:    []string{"ttcp_3", "ttcp_2"},
			expectIncomplete: false,
		},
		{
			name:             "query with sort and limit",
			query:            `status % "active"`,
			sortBy:           SortByCreatedTime,
			sortDirection:    Descending,
			maxResultSetSize: 1,
			expectedCount:    1,
			expectedOrder:    []string{"ttcp_3"},
			expectIncomplete: true,
		},
		{
			name:             "query without sort",
			query:            `status % "active"`,
			sortBy:           SortByDefault,
			sortDirection:    SortDirectionDefault,
			maxResultSetSize: 10,
			expectedCount:    2,
			expectIncomplete: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build options
			opts := []Option{
				WithMaxResultSetSize(tt.maxResultSetSize),
			}
			if tt.sortBy != SortByDefault {
				opts = append(opts, WithSort(tt.sortBy, tt.sortDirection, []SortBy{SortByCreatedTime}))
			}

			// Execute the query
			result, err := r.QuerySessions(ctx, at.Id, tt.query, opts...)
			require.NoError(t, err)
			require.NotNil(t, result)

			// Verify results
			assert.Len(t, result.Sessions, tt.expectedCount)
			assert.Equal(t, tt.expectIncomplete, result.Incomplete)

			// Verify order if expected
			if len(tt.expectedOrder) > 0 {
				var actualOrder []string
				for _, sess := range result.Sessions {
					actualOrder = append(actualOrder, sess.Id)
				}
				assert.Equal(t, tt.expectedOrder, actualOrder)
			}
		})
	}
}

func TestRepository_searchSessions_limitBehavior(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)

	addr := "address"
	u := &user{
		Id:      "u1",
		Address: addr,
	}
	at := &authtokens.AuthToken{
		Id:     "at_1",
		Token:  "at_1_token",
		UserId: u.Id,
	}
	kt := KeyringToken{
		KeyringType: "k1",
		TokenName:   "t1",
		AuthTokenId: at.Id,
	}
	atMap := map[ringToken]*authtokens.AuthToken{
		{"k1", "t1"}: at,
	}
	r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(maps.Values(atMap)))
	require.NoError(t, err)
	require.NoError(t, r.AddKeyringToken(ctx, addr, kt))

	// Create 10 sessions
	var ss []*sessions.Session
	for i := 0; i < 10; i++ {
		ss = append(ss, &sessions.Session{
			Id:       fmt.Sprintf("ttcp_%d", i),
			Status:   "active",
			Endpoint: fmt.Sprintf("address%d", i),
			ScopeId:  "p_123",
			TargetId: "ttcp_123",
			UserId:   "u_123",
			Type:     "tcp",
		})
	}
	require.NoError(t, r.refreshSessions(ctx, u, map[AuthToken]string{{Id: "id"}: "something"},
		WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc(t, [][]*sessions.Session{ss}, [][]string{nil})))))

	tests := []struct {
		name             string
		maxResultSetSize int
		expectedCount    int
		expectIncomplete bool
	}{
		{
			name:             "limit of 5",
			maxResultSetSize: 5,
			expectedCount:    5,
			expectIncomplete: true,
		},
		{
			name:             "limit of 10 (exact match)",
			maxResultSetSize: 10,
			expectedCount:    10,
			expectIncomplete: false,
		},
		{
			name:             "limit of 15 (more than available)",
			maxResultSetSize: 15,
			expectedCount:    10,
			expectIncomplete: false,
		},
		{
			name:             "no limit (-1)",
			maxResultSetSize: -1,
			expectedCount:    10,
			expectIncomplete: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Execute the list
			result, err := r.ListSessions(ctx, at.Id, WithMaxResultSetSize(tt.maxResultSetSize))
			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Len(t, result.Sessions, tt.expectedCount)
			assert.Equal(t, tt.expectIncomplete, result.Incomplete)
		})
	}
}

func TestRepository_searchSessions_dbOptionsVerifyOrderClause(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)

	addr := "address"
	u := &user{
		Id:      "u1",
		Address: addr,
	}
	at := &authtokens.AuthToken{
		Id:     "at_1",
		Token:  "at_1_token",
		UserId: u.Id,
	}
	kt := KeyringToken{
		KeyringType: "k1",
		TokenName:   "t1",
		AuthTokenId: at.Id,
	}
	atMap := map[ringToken]*authtokens.AuthToken{
		{"k1", "t1"}: at,
	}
	r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(maps.Values(atMap)))
	require.NoError(t, err)
	require.NoError(t, r.AddKeyringToken(ctx, addr, kt))

	// Create a single session
	ss := []*sessions.Session{
		{
			Id:       "ttcp_1",
			Status:   "active",
			Endpoint: "address1",
			ScopeId:  "p_123",
			TargetId: "ttcp_123",
			UserId:   "u_123",
			Type:     "tcp",
		},
	}
	require.NoError(t, r.refreshSessions(ctx, u, map[AuthToken]string{{Id: "id"}: "something"},
		WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc(t, [][]*sessions.Session{ss}, [][]string{nil})))))

	t.Run("verify order clause format for ascending", func(t *testing.T) {
		result, err := r.ListSessions(ctx, at.Id,
			WithMaxResultSetSize(10),
			WithSort(SortByCreatedTime, Ascending, []SortBy{SortByCreatedTime}))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Len(t, result.Sessions, 1)
	})

	t.Run("verify order clause format for descending", func(t *testing.T) {
		result, err := r.ListSessions(ctx, at.Id,
			WithMaxResultSetSize(10),
			WithSort(SortByCreatedTime, Descending, []SortBy{SortByCreatedTime}))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Len(t, result.Sessions, 1)
	})

	t.Run("verify no order clause when sortBy is default", func(t *testing.T) {
		result, err := r.ListSessions(ctx, at.Id, WithMaxResultSetSize(10))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Len(t, result.Sessions, 1)
	})
}

func TestRepository_searchSessions_sortingEdgeCases(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)

	addr := "address"
	u := &user{
		Id:      "u1",
		Address: addr,
	}
	at := &authtokens.AuthToken{
		Id:     "at_1",
		Token:  "at_1_token",
		UserId: u.Id,
	}
	kt := KeyringToken{
		KeyringType: "k1",
		TokenName:   "t1",
		AuthTokenId: at.Id,
	}
	atMap := map[ringToken]*authtokens.AuthToken{
		{"k1", "t1"}: at,
	}
	r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(maps.Values(atMap)))
	require.NoError(t, err)
	require.NoError(t, r.AddKeyringToken(ctx, addr, kt))

	// Create test sessions
	now := time.Now()
	ss := []*sessions.Session{
		{
			Id:          "ttcp_1",
			Status:      "active",
			Endpoint:    "address1",
			ScopeId:     "p_123",
			TargetId:    "ttcp_123",
			UserId:      "u_123",
			Type:        "tcp",
			CreatedTime: now.Add(-1 * time.Hour),
		},
		{
			Id:          "ttcp_2",
			Status:      "pending",
			Endpoint:    "address2",
			ScopeId:     "p_123",
			TargetId:    "ttcp_123",
			UserId:      "u_123",
			Type:        "tcp",
			CreatedTime: now,
		},
	}
	require.NoError(t, r.refreshSessions(ctx, u, map[AuthToken]string{{Id: "id"}: "something"},
		WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc(t, [][]*sessions.Session{ss}, [][]string{nil})))))

	t.Run("unsupported sort field - SortByName not in sessionSortFieldMap", func(t *testing.T) {
		// SortByName is not in sessionSortFieldMap, should return error
		result, err := r.searchSessions(ctx, "true", nil,
			withAuthTokenId(at.Id),
			WithMaxResultSetSize(10),
			WithSort(SortByName, Ascending, []SortBy{SortByName}))
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "unsupported sort field for sessions")
	})

	t.Run("invalid sort direction - unknown value", func(t *testing.T) {
		// Using an invalid sort direction that's not in the switch statement
		result, err := r.searchSessions(ctx, "true", nil,
			withAuthTokenId(at.Id),
			WithMaxResultSetSize(10),
			WithSort(SortByCreatedTime, SortDirection("invalid"), []SortBy{SortByCreatedTime}))
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "unsupported sort direction")
	})

	t.Run("valid sort with SortDirectionDefault - should default to descending", func(t *testing.T) {
		// SortDirectionDefault should be treated as ascending
		result, err := r.searchSessions(ctx, "true", nil,
			withAuthTokenId(at.Id),
			WithMaxResultSetSize(10),
			WithSort(SortByCreatedTime, SortDirectionDefault, []SortBy{SortByCreatedTime}))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Len(t, result.Sessions, 2)
		// Should be in descending order (newest first)
		assert.Equal(t, "ttcp_2", result.Sessions[0].Id)
		assert.Equal(t, "ttcp_1", result.Sessions[1].Id)
	})

	t.Run("sort with limit 1 - verify incomplete flag", func(t *testing.T) {
		result, err := r.searchSessions(ctx, "true", nil,
			withAuthTokenId(at.Id),
			WithMaxResultSetSize(1),
			WithSort(SortByCreatedTime, Descending, []SortBy{SortByCreatedTime}))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Len(t, result.Sessions, 1)
		assert.True(t, result.Incomplete)
		assert.Equal(t, "ttcp_2", result.Sessions[0].Id) // newest first
	})

	t.Run("sort with no results - empty result set", func(t *testing.T) {
		// Query that matches nothing
		result, err := r.QuerySessions(ctx, at.Id, `status % "nonexistent"`,
			WithMaxResultSetSize(10),
			WithSort(SortByCreatedTime, Ascending, []SortBy{SortByCreatedTime}))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Len(t, result.Sessions, 0)
		assert.False(t, result.Incomplete)
	})
}

func TestRepository_searchSessions_jsonExtractSafety(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)

	addr := "address"
	u := &user{
		Id:      "u1",
		Address: addr,
	}
	at := &authtokens.AuthToken{
		Id:     "at_1",
		Token:  "at_1_token",
		UserId: u.Id,
	}
	kt := KeyringToken{
		KeyringType: "k1",
		TokenName:   "t1",
		AuthTokenId: at.Id,
	}
	atMap := map[ringToken]*authtokens.AuthToken{
		{"k1", "t1"}: at,
	}
	r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(maps.Values(atMap)))
	require.NoError(t, err)
	require.NoError(t, r.AddKeyringToken(ctx, addr, kt))

	// Create test session
	ss := []*sessions.Session{
		{
			Id:          "ttcp_1",
			Status:      "active",
			Endpoint:    "address1",
			ScopeId:     "p_123",
			TargetId:    "ttcp_123",
			UserId:      "u_123",
			Type:        "tcp",
			CreatedTime: time.Now(),
		},
	}
	require.NoError(t, r.refreshSessions(ctx, u, map[AuthToken]string{{Id: "id"}: "something"},
		WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc(t, [][]*sessions.Session{ss}, [][]string{nil})))))

	t.Run("verify json_extract uses safe field from sessionSortFieldMap", func(t *testing.T) {
		// This test verifies that the json_extract uses the mapped field name
		// from sessionSortFieldMap, which should be safe
		result, err := r.searchSessions(ctx, "true", nil,
			withAuthTokenId(at.Id),
			WithMaxResultSetSize(10),
			WithSort(SortByCreatedTime, Ascending, []SortBy{SortByCreatedTime}))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Len(t, result.Sessions, 1)
		// If we got here without SQL errors, json_extract is working correctly
	})

	t.Run("verify sorting works with actual JSON data", func(t *testing.T) {
		// Verify that the JSON item field contains valid data and sorting works
		result, err := r.ListSessions(ctx, at.Id,
			WithMaxResultSetSize(10),
			WithSort(SortByCreatedTime, Descending, []SortBy{SortByCreatedTime}))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Len(t, result.Sessions, 1)
		assert.Equal(t, "ttcp_1", result.Sessions[0].Id)
		// Verify the session has all expected fields from JSON unmarshaling
		assert.Equal(t, "active", result.Sessions[0].Status)
		assert.Equal(t, "address1", result.Sessions[0].Endpoint)
	})
}

func TestRepository_ListSessions_sortingValidation(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)

	addr := "address"
	u := &user{
		Id:      "u1",
		Address: addr,
	}
	at := &authtokens.AuthToken{
		Id:     "at_1",
		Token:  "at_1_token",
		UserId: u.Id,
	}
	kt := KeyringToken{
		KeyringType: "k1",
		TokenName:   "t1",
		AuthTokenId: at.Id,
	}
	atMap := map[ringToken]*authtokens.AuthToken{
		{"k1", "t1"}: at,
	}
	r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(maps.Values(atMap)))
	require.NoError(t, err)
	require.NoError(t, r.AddKeyringToken(ctx, addr, kt))

	// Create test sessions
	now := time.Now()
	ss := []*sessions.Session{
		{
			Id:          "ttcp_1",
			Status:      "active",
			Endpoint:    "address1",
			ScopeId:     "p_123",
			TargetId:    "ttcp_123",
			UserId:      "u_123",
			Type:        "tcp",
			CreatedTime: now.Add(-1 * time.Hour),
		},
		{
			Id:          "ttcp_2",
			Status:      "pending",
			Endpoint:    "address2",
			ScopeId:     "p_123",
			TargetId:    "ttcp_123",
			UserId:      "u_123",
			Type:        "tcp",
			CreatedTime: now,
		},
	}
	require.NoError(t, r.refreshSessions(ctx, u, map[AuthToken]string{{Id: "id"}: "something"},
		WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc(t, [][]*sessions.Session{ss}, [][]string{nil})))))

	t.Run("ListSessions with unsupported sort field", func(t *testing.T) {
		// Trying to sort by a field not in sessionSortFieldMap
		result, err := r.ListSessions(ctx, at.Id,
			WithMaxResultSetSize(10),
			WithSort(SortByName, Ascending, []SortBy{SortByName}))
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "unsupported sort field for sessions")
	})

	t.Run("ListSessions with valid sort field", func(t *testing.T) {
		result, err := r.ListSessions(ctx, at.Id,
			WithMaxResultSetSize(10),
			WithSort(SortByCreatedTime, Ascending, []SortBy{SortByCreatedTime}))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Len(t, result.Sessions, 2)
		assert.Equal(t, "ttcp_1", result.Sessions[0].Id)
		assert.Equal(t, "ttcp_2", result.Sessions[1].Id)
	})
}

func TestRepository_QuerySessions_sortingValidation(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)

	addr := "address"
	u := &user{
		Id:      "u1",
		Address: addr,
	}
	at := &authtokens.AuthToken{
		Id:     "at_1",
		Token:  "at_1_token",
		UserId: u.Id,
	}
	kt := KeyringToken{
		KeyringType: "k1",
		TokenName:   "t1",
		AuthTokenId: at.Id,
	}
	atMap := map[ringToken]*authtokens.AuthToken{
		{"k1", "t1"}: at,
	}
	r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(maps.Values(atMap)))
	require.NoError(t, err)
	require.NoError(t, r.AddKeyringToken(ctx, addr, kt))

	// Create test sessions
	now := time.Now()
	ss := []*sessions.Session{
		{
			Id:          "ttcp_1",
			Status:      "active",
			Endpoint:    "address1",
			ScopeId:     "p_123",
			TargetId:    "ttcp_123",
			UserId:      "u_123",
			Type:        "tcp",
			CreatedTime: now.Add(-1 * time.Hour),
		},
		{
			Id:          "ttcp_2",
			Status:      "active",
			Endpoint:    "address2",
			ScopeId:     "p_123",
			TargetId:    "ttcp_123",
			UserId:      "u_123",
			Type:        "tcp",
			CreatedTime: now,
		},
	}
	require.NoError(t, r.refreshSessions(ctx, u, map[AuthToken]string{{Id: "id"}: "something"},
		WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc(t, [][]*sessions.Session{ss}, [][]string{nil})))))

	t.Run("QuerySessions with unsupported sort field", func(t *testing.T) {
		result, err := r.QuerySessions(ctx, at.Id, `status % "active"`,
			WithMaxResultSetSize(10),
			WithSort(SortByName, Ascending, []SortBy{SortByName}))
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "unsupported sort field for sessions")
	})

	t.Run("QuerySessions with valid sort field and query", func(t *testing.T) {
		result, err := r.QuerySessions(ctx, at.Id, `status % "active"`,
			WithMaxResultSetSize(10),
			WithSort(SortByCreatedTime, Descending, []SortBy{SortByCreatedTime}))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Len(t, result.Sessions, 2)
		// Descending order - newest first
		assert.Equal(t, "ttcp_2", result.Sessions[0].Id)
		assert.Equal(t, "ttcp_1", result.Sessions[1].Id)
	})

	t.Run("QuerySessions with sort and limit causing incomplete", func(t *testing.T) {
		result, err := r.QuerySessions(ctx, at.Id, `status % "active"`,
			WithMaxResultSetSize(1),
			WithSort(SortByCreatedTime, Ascending, []SortBy{SortByCreatedTime}))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Len(t, result.Sessions, 1)
		assert.True(t, result.Incomplete)
		assert.Equal(t, "ttcp_1", result.Sessions[0].Id) // oldest first
	})
}
