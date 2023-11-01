// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package search

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/clientcache/internal/daemon"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testCommander struct {
	t  *testing.T
	at *authtokens.AuthToken
}

func (r *testCommander) Client(opt ...base.Option) (*api.Client, error) {
	client, err := api.NewClient(nil)
	require.NoError(r.t, err)
	return client, nil
}

func (r *testCommander) ReadTokenFromKeyring(k, a string) *authtokens.AuthToken {
	return r.at
}

func TestSearch(t *testing.T) {
	ctx := context.Background()
	at := &authtokens.AuthToken{
		Id:             "at_1",
		UserId:         "user_1",
		Token:          "at_1_token",
		ExpirationTime: time.Now().Add(time.Minute),
	}
	cmd := &testCommander{t: t, at: at}
	boundaryTokenReaderFn := func(ctx context.Context, addr, authToken string) (*authtokens.AuthToken, error) {
		if authToken == at.Token {
			return at, nil
		}
		return nil, errors.New("test not found error")
	}

	srv := daemon.NewTestServer(t, cmd)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv.Serve(t, daemon.WithBoundaryTokenReaderFunc(ctx, boundaryTokenReaderFn))
	}()
	// Give the store some time to get initialized
	time.Sleep(100 * time.Millisecond)
	srv.AddKeyringToken(t, "address", "keyringtype", "tokenname", at.Id, boundaryTokenReaderFn)

	errorCases := []struct {
		name           string
		fb             filterBy
		apiErrContains string
	}{
		{
			name: "no resource",
			fb: filterBy{
				flagQuery:   "name=name",
				authTokenId: at.Id,
			},
			apiErrContains: "resource is a required field but was empty",
		},
		{
			name: "bad resource",
			fb: filterBy{
				authTokenId: at.Id,
				flagQuery:   "name=name",
				resource:    "hosts",
			},
			apiErrContains: "provided resource is not a valid searchable resource",
		},
		{
			name: "unknown auth token id",
			fb: filterBy{
				authTokenId: "unknown",
				flagQuery:   "description % tar",
				resource:    "targets",
			},
			apiErrContains: "Forbidden",
		},
		{
			name: "unsupported column",
			fb: filterBy{
				authTokenId: at.Id,
				flagQuery:   "item % 'tar'",
				resource:    "targets",
			},
			apiErrContains: "invalid column \"item\"",
		},
	}

	for _, tc := range errorCases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := search(ctx, srv.BaseDotDir(), tc.fb)
			require.NoError(t, err)
			r := daemon.SearchResult{}
			apiErr, err := resp.Decode(&r)
			assert.NoError(t, err)
			assert.NotNil(t, apiErr)
			assert.Contains(t, apiErr.Message, tc.apiErrContains)
		})
	}

	t.Run("empty response from list", func(t *testing.T) {
		resp, err := search(ctx, srv.BaseDotDir(), filterBy{
			authTokenId: at.Id,
			resource:    "targets",
		})
		require.NoError(t, err)
		r := daemon.SearchResult{}
		apiErr, err := resp.Decode(&r)
		assert.NoError(t, err)
		assert.Nil(t, apiErr)
		assert.NotNil(t, r)
		assert.EqualValues(t, r, daemon.SearchResult{})
	})

	t.Run("empty response from query", func(t *testing.T) {
		resp, err := search(ctx, srv.BaseDotDir(), filterBy{
			authTokenId: at.Id,
			flagQuery:   "name=name",
			resource:    "targets",
		})
		require.NoError(t, err)
		r := daemon.SearchResult{}
		apiErr, err := resp.Decode(&r)
		assert.NoError(t, err)
		assert.Nil(t, apiErr)
		assert.NotNil(t, r)
		assert.EqualValues(t, r, daemon.SearchResult{})
	})

	srv.AddResources(t, cmd.at, []*targets.Target{
		{Id: "ttcp_1234567890", Name: "name1", Description: "description1"},
		{Id: "ttcp_0987654321", Name: "name2", Description: "description2"},
	}, []*sessions.Session{
		{Id: "sess_1234567890", TargetId: "ttcp_1234567890", Status: "pending"},
		{Id: "sess_0987654321", TargetId: "ttcp_0987654321", Status: "pending"},
	}, boundaryTokenReaderFn)

	t.Run("target response from list", func(t *testing.T) {
		resp, err := search(ctx, srv.BaseDotDir(), filterBy{
			authTokenId: at.Id,
			resource:    "targets",
		})
		require.NoError(t, err)
		r := daemon.SearchResult{}
		apiErr, err := resp.Decode(&r)
		assert.NoError(t, err)
		assert.Nil(t, apiErr)
		assert.NotNil(t, r)
		assert.Len(t, r.Targets, 2)
	})
	t.Run("full target response from query", func(t *testing.T) {
		resp, err := search(ctx, srv.BaseDotDir(), filterBy{
			authTokenId: at.Id,
			flagQuery:   "id % ttcp",
			resource:    "targets",
		})
		require.NoError(t, err)
		r := daemon.SearchResult{}
		apiErr, err := resp.Decode(&r)
		assert.NoError(t, err)
		assert.Nil(t, apiErr)
		assert.NotNil(t, r)
		assert.Len(t, r.Targets, 2)
	})
	t.Run("partial target response from query", func(t *testing.T) {
		resp, err := search(ctx, srv.BaseDotDir(), filterBy{
			authTokenId: at.Id,
			flagQuery:   "id % ttcp_1234567890",
			resource:    "targets",
		})
		require.NoError(t, err)
		r := daemon.SearchResult{}
		apiErr, err := resp.Decode(&r)
		assert.NoError(t, err)
		assert.Nil(t, apiErr)
		assert.NotNil(t, r)
		assert.Len(t, r.Sessions, 0)
		assert.Len(t, r.Targets, 1)
	})

	t.Run("session response from list", func(t *testing.T) {
		resp, err := search(ctx, srv.BaseDotDir(), filterBy{
			authTokenId: at.Id,
			resource:    "sessions",
		})
		require.NoError(t, err)
		r := daemon.SearchResult{}
		apiErr, err := resp.Decode(&r)
		assert.NoError(t, err)
		assert.Nil(t, apiErr)
		assert.NotNil(t, r)
		assert.Len(t, r.Targets, 0)
		assert.Len(t, r.Sessions, 2)
	})
	t.Run("full session response from query", func(t *testing.T) {
		resp, err := search(ctx, srv.BaseDotDir(), filterBy{
			authTokenId: at.Id,
			flagQuery:   "id % sess",
			resource:    "sessions",
		})
		require.NoError(t, err)
		r := daemon.SearchResult{}
		apiErr, err := resp.Decode(&r)
		assert.NoError(t, err)
		assert.Nil(t, apiErr)
		assert.NotNil(t, r)
		assert.Len(t, r.Sessions, 2)
	})
	t.Run("partial session response from query", func(t *testing.T) {
		resp, err := search(ctx, srv.BaseDotDir(), filterBy{
			authTokenId: at.Id,
			flagQuery:   "id % sess_1234567890",
			resource:    "sessions",
		})
		require.NoError(t, err)
		r := daemon.SearchResult{}
		apiErr, err := resp.Decode(&r)
		assert.NoError(t, err)
		assert.Nil(t, apiErr)
		assert.NotNil(t, r)
		assert.Len(t, r.Sessions, 1)
	})
}
