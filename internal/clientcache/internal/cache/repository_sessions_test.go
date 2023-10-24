// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"sync"
	"testing"

	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/api/targets"
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
			err := r.refreshSessions(ctx, tc.u, map[AuthToken]string{{Id: "id"}: "something"},
				WithSessionRetrievalFunc(testStaticResourceRetrievalFunc(t, [][]*sessions.Session{tc.sess}, [][]string{nil})))
			if tc.errorContains == "" {
				assert.NoError(t, err)
				rw := db.New(s)
				var got []*Session
				require.NoError(t, rw.SearchWhere(ctx, &got, "true", nil))
				assert.Len(t, got, tc.wantCount)

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
				Type:     "tcp",
			},
			{
				Id:       "ttcp_2",
				Status:   "status2",
				Endpoint: "address2",
				Type:     "tcp",
			},
		},
		{
			{
				Id:       "ttcp_3",
				Status:   "status3",
				Endpoint: "address3",
				Type:     "tcp",
			},
		},
	}

	err = r.refreshSessions(ctx, &u, map[AuthToken]string{{Id: "id"}: "something"},
		WithSessionRetrievalFunc(testStaticResourceRetrievalFunc(t, ss, [][]string{nil, nil})))
	assert.NoError(t, err)

	got, err := r.ListSessions(ctx, at.Id)
	require.NoError(t, err)
	assert.Len(t, got, 2)

	// Refreshing again uses the refresh token and get additional sessions, appending
	// them to the response
	err = r.refreshSessions(ctx, &u, map[AuthToken]string{{Id: "id"}: "something"},
		WithSessionRetrievalFunc(testStaticResourceRetrievalFunc(t, ss, [][]string{nil, nil})))
	assert.NoError(t, err)

	got, err = r.ListSessions(ctx, at.Id)
	require.NoError(t, err)
	assert.Len(t, got, 3)

	// Refreshing again wont return any more resources, but also none should be
	// removed
	require.NoError(t, r.refreshSessions(ctx, &u, map[AuthToken]string{{Id: "id"}: "something"},
		WithSessionRetrievalFunc(testStaticResourceRetrievalFunc(t, ss, [][]string{nil, nil}))))
	assert.NoError(t, err)

	got, err = r.ListSessions(ctx, at.Id)
	require.NoError(t, err)
	assert.Len(t, got, 3)

	// Refresh again with the refresh token being reported as invalid.
	require.NoError(t, r.refreshSessions(ctx, &u, map[AuthToken]string{{Id: "id"}: "something"},
		WithSessionRetrievalFunc(testErroringForRefreshTokenRetrievalFunc(t, ss[0]))))
	assert.NoError(t, err)

	got, err = r.ListSessions(ctx, at.Id)
	require.NoError(t, err)
	assert.Len(t, got, 2)
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
	require.NoError(t, r.refreshSessions(ctx, u1, map[AuthToken]string{{Id: "id"}: "something"},
		WithSessionRetrievalFunc(testStaticResourceRetrievalFunc(t, [][]*sessions.Session{ss}, [][]string{nil}))))

	t.Run("wrong user gets no sessions", func(t *testing.T) {
		l, err := r.ListSessions(ctx, kt2.AuthTokenId)
		assert.NoError(t, err)
		assert.Empty(t, l)
	})
	t.Run("correct token gets sessions", func(t *testing.T) {
		l, err := r.ListSessions(ctx, kt1.AuthTokenId)
		assert.NoError(t, err)
		assert.Len(t, l, len(ss))
		assert.ElementsMatch(t, l, ss)
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
	require.NoError(t, r.refreshSessions(ctx, u1, map[AuthToken]string{{Id: "id"}: "something"},
		WithSessionRetrievalFunc(testStaticResourceRetrievalFunc(t, [][]*sessions.Session{ss}, [][]string{nil}))))

	t.Run("wrong token gets no sessions", func(t *testing.T) {
		l, err := r.QuerySessions(ctx, kt2.AuthTokenId, query)
		assert.NoError(t, err)
		assert.Empty(t, l)
	})
	t.Run("correct token gets sessions", func(t *testing.T) {
		l, err := r.QuerySessions(ctx, kt1.AuthTokenId, query)
		assert.NoError(t, err)
		assert.Len(t, l, 2)
		assert.ElementsMatch(t, l, ss[0:2])
	})
}

func TestDefaultSessionRetrievalFunc(t *testing.T) {
	tc := controller.NewTestController(t, nil)
	tc.Client().SetToken(tc.Token().Token)
	tarClient := targets.NewClient(tc.Client())
	_ = worker.NewTestWorker(t, &worker.TestWorkerOpts{
		Name:             "test",
		InitialUpstreams: tc.ClusterAddrs(),
		WorkerAuthKms:    tc.Config().WorkerAuthKms,
	})

	tar1, err := tarClient.Create(tc.Context(), "tcp", "p_1234567890", targets.WithName("tar1"), targets.WithTcpTargetDefaultPort(1), targets.WithAddress("address"))
	require.NoError(t, err)
	require.NotNil(t, tar1)

	require.NoError(t, tc.WaitForNextWorkerStatusUpdate("test"))
	_, err = tarClient.AuthorizeSession(tc.Context(), tar1.Item.Id)
	require.NoError(t, err)

	got, removed, refTok, err := defaultSessionFunc(tc.Context(), tc.ApiAddrs()[0], tc.Token().Token, "")
	assert.NoError(t, err)
	assert.NotEmpty(t, refTok)
	assert.Empty(t, removed)
	assert.Len(t, got, 1)

	got2, removed2, refTok2, err := defaultSessionFunc(tc.Context(), tc.ApiAddrs()[0], tc.Token().Token, refTok)
	assert.NoError(t, err)
	assert.NotEmpty(t, refTok2)
	assert.Empty(t, removed2)
	_ = got2
	t.Skip("This is skipped while waiting for PR 3897 to be merged")
	assert.Empty(t, got2)
}
