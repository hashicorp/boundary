// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"sync"
	"testing"

	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/api/targets"
	cachedb "github.com/hashicorp/boundary/internal/clientcache/internal/db"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSearchService(t *testing.T) {
	ctx := context.Background()

	t.Run("nil repo", func(t *testing.T) {
		ss, err := NewSearchService(ctx, nil)
		assert.Error(t, err)
		assert.ErrorContains(t, err, "repo is nil")
		assert.Nil(t, ss)
	})

	t.Run("success", func(t *testing.T) {
		s, err := cachedb.Open(ctx)
		require.NoError(t, err)
		r, err := NewRepository(ctx, s, &sync.Map{},
			mapBasedAuthTokenKeyringLookup(nil),
			sliceBasedAuthTokenBoundaryReader(nil))
		assert.NoError(t, err)

		ss, err := NewSearchService(ctx, r)
		assert.NoError(t, err)
		assert.NotNil(t, ss)
	})
}

func TestSearch_Errors(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)
	r, err := NewRepository(ctx, s, &sync.Map{},
		mapBasedAuthTokenKeyringLookup(nil),
		sliceBasedAuthTokenBoundaryReader(nil))
	assert.NoError(t, err)

	ss, err := NewSearchService(ctx, r)
	require.NoError(t, err)
	require.NotNil(t, ss)

	cases := []struct {
		name          string
		params        SearchParams
		errorContains string
	}{
		{
			name: "missing resource",
			params: SearchParams{
				Resource:    "",
				AuthTokenId: "at_1",
			},
			errorContains: "invalid resource",
		},
		{
			name: "missing auth token id",
			params: SearchParams{
				Resource:    "targets",
				AuthTokenId: "",
			},
			errorContains: "missing auth token id",
		},
		{
			name: "unrecognized resource",
			params: SearchParams{
				Resource:    "unknown",
				AuthTokenId: "at_1",
			},
			errorContains: "invalid resource",
		},
		{
			name: "bad filter",
			params: SearchParams{
				Resource:    "targets",
				AuthTokenId: "at_1",
				Filter:      "unknown=filter?syntax!",
			},
			errorContains: "couldn't build filter",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := ss.Search(ctx, tc.params)
			assert.Error(t, err)
			assert.ErrorContains(t, err, tc.errorContains)
			assert.Nil(t, res)
		})
	}
}

func TestSearch(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)

	at := &AuthToken{
		Id:     "at_1",
		UserId: "u_1",
	}
	{
		u := &user{Id: at.UserId, Address: "address"}
		rw := db.New(s)
		require.NoError(t, rw.Create(ctx, u))
		require.NoError(t, rw.Create(ctx, at))

		targets := []any{
			&Target{OwnerUserId: u.Id, Id: "t_1", Name: "one", Type: "tcp", Item: `{"id": "t_1", "name": "one", "type": "tcp"}`},
			&Target{OwnerUserId: u.Id, Id: "t_2", Name: "two", Type: "tcp", Item: `{"id": "t_2", "name": "two", "type": "tcp"}`},
		}
		require.NoError(t, rw.CreateItems(ctx, targets))

		sessions := []any{
			&Session{OwnerUserId: u.Id, Id: "s_1", Endpoint: "one", Type: "tcp", UserId: "u123", Item: `{"id": "s_1", "endpoint": "one", "type": "tcp", "user_id": "u123"}`},
			&Session{OwnerUserId: u.Id, Id: "s_2", Endpoint: "two", Type: "ssh", UserId: "u321", Item: `{"id": "s_2", "endpoint": "two", "type": "ssh", "user_id": "u321"}`},
		}
		require.NoError(t, rw.CreateItems(ctx, sessions))
	}

	r, err := NewRepository(ctx, s, &sync.Map{},
		mapBasedAuthTokenKeyringLookup(nil),
		sliceBasedAuthTokenBoundaryReader(nil))
	assert.NoError(t, err)

	ss, err := NewSearchService(ctx, r)
	require.NoError(t, err)
	require.NotNil(t, ss)

	t.Run("List targets", func(t *testing.T) {
		got, err := ss.Search(ctx, SearchParams{
			Resource:    "targets",
			AuthTokenId: at.Id,
		})
		assert.NoError(t, err)
		assert.EqualValues(t, &SearchResult{Targets: []*targets.Target{
			{Id: "t_1", Name: "one", Type: "tcp"},
			{Id: "t_2", Name: "two", Type: "tcp"},
		}}, got)
	})

	t.Run("query targets", func(t *testing.T) {
		got, err := ss.Search(ctx, SearchParams{
			Resource:    "targets",
			AuthTokenId: at.Id,
			Query:       `name="one"`,
		})
		assert.NoError(t, err)
		assert.EqualValues(t, &SearchResult{Targets: []*targets.Target{
			{Id: "t_1", Name: "one", Type: "tcp"},
		}}, got)
	})

	t.Run("query targets on type", func(t *testing.T) {
		got, err := ss.Search(ctx, SearchParams{
			Resource:    "targets",
			AuthTokenId: at.Id,
			Query:       `type="tcp"`,
		})
		assert.NoError(t, err)
		assert.EqualValues(t, &SearchResult{Targets: []*targets.Target{
			{Id: "t_1", Name: "one", Type: "tcp"},
			{Id: "t_2", Name: "two", Type: "tcp"},
		}}, got)
	})

	t.Run("query targets bad column", func(t *testing.T) {
		got, err := ss.Search(ctx, SearchParams{
			Resource:    "targets",
			AuthTokenId: at.Id,
			Query:       `item % "one"`,
		})
		assert.Error(t, err)
		assert.ErrorContains(t, err, `invalid column "item"`)
		assert.Nil(t, got)
	})

	t.Run("query targets bad column owner user id", func(t *testing.T) {
		got, err := ss.Search(ctx, SearchParams{
			Resource:    "targets",
			AuthTokenId: at.Id,
			Query:       `owner_user_id % "u"`,
		})
		assert.Error(t, err)
		assert.ErrorContains(t, err, `invalid column "owner_user_id"`)
		assert.Nil(t, got)
	})

	t.Run("Filter targets", func(t *testing.T) {
		got, err := ss.Search(ctx, SearchParams{
			Resource:    "targets",
			AuthTokenId: at.Id,
			Filter:      `"/item/name" matches "one"`,
		})
		assert.NoError(t, err)
		assert.EqualValues(t, &SearchResult{Targets: []*targets.Target{
			{Id: "t_1", Name: "one", Type: "tcp"},
		}}, got)
	})

	t.Run("List sessions", func(t *testing.T) {
		got, err := ss.Search(ctx, SearchParams{
			Resource:    "sessions",
			AuthTokenId: at.Id,
		})
		assert.NoError(t, err)
		assert.EqualValues(t, &SearchResult{Sessions: []*sessions.Session{
			{Id: "s_1", Endpoint: "one", Type: "tcp", UserId: "u123"},
			{Id: "s_2", Endpoint: "two", Type: "ssh", UserId: "u321"},
		}}, got)
	})

	t.Run("query sessions", func(t *testing.T) {
		got, err := ss.Search(ctx, SearchParams{
			Resource:    "sessions",
			AuthTokenId: at.Id,
			Query:       `endpoint="one"`,
		})
		assert.NoError(t, err)
		assert.EqualValues(t, &SearchResult{Sessions: []*sessions.Session{
			{Id: "s_1", Endpoint: "one", Type: "tcp", UserId: "u123"},
		}}, got)
	})

	t.Run("query sessions user id", func(t *testing.T) {
		got, err := ss.Search(ctx, SearchParams{
			Resource:    "sessions",
			AuthTokenId: at.Id,
			Query:       `user_id="u123"`,
		})
		assert.NoError(t, err)
		assert.EqualValues(t, &SearchResult{Sessions: []*sessions.Session{
			{Id: "s_1", Endpoint: "one", Type: "tcp", UserId: "u123"},
		}}, got)
	})

	t.Run("query sessions bad column owner user id", func(t *testing.T) {
		got, err := ss.Search(ctx, SearchParams{
			Resource:    "sessions",
			AuthTokenId: at.Id,
			Query:       `owner_user_id % "u"`,
		})
		assert.Error(t, err)
		assert.ErrorContains(t, err, `invalid column "owner_user_id"`)
		assert.Nil(t, got)
	})

	t.Run("Filter sessions", func(t *testing.T) {
		got, err := ss.Search(ctx, SearchParams{
			Resource:    "sessions",
			AuthTokenId: at.Id,
			Filter:      `"/item/endpoint" matches "one"`,
		})
		assert.NoError(t, err)
		assert.EqualValues(t, &SearchResult{Sessions: []*sessions.Session{
			{Id: "s_1", Endpoint: "one", Type: "tcp", UserId: "u123"},
		}}, got)
	})

	t.Run("unrecognized auth token", func(t *testing.T) {
		got, err := ss.Search(ctx, SearchParams{
			Resource:    "targets",
			AuthTokenId: "unrecognized",
		})
		assert.NoError(t, err)
		assert.Equal(t, &SearchResult{Targets: []*targets.Target{}}, got)
	})
}
