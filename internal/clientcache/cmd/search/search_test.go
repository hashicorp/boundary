// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package search

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/aliases"
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
	at map[string]*authtokens.AuthToken
}

func (r *testCommander) Client(opt ...base.Option) (*api.Client, error) {
	client, err := api.NewClient(nil)
	require.NoError(r.t, err)
	return client, nil
}

func (r *testCommander) ReadTokenFromKeyring(k, a string) (*authtokens.AuthToken, error) {
	return r.at[a], nil
}

func TestSearch(t *testing.T) {
	ctx := context.Background()
	at := &authtokens.AuthToken{
		Id:             "at_1",
		UserId:         "user_1",
		Token:          "at_1_token",
		ExpirationTime: time.Now().Add(time.Minute),
	}
	unsupportedAt := &authtokens.AuthToken{
		Id:             "at_2",
		UserId:         "user_2",
		Token:          "at_2_token",
		ExpirationTime: time.Now().Add(time.Minute),
	}
	cmd := &testCommander{
		t:  t,
		at: map[string]*authtokens.AuthToken{"tokenname": at, "unsupported": unsupportedAt},
	}
	boundaryTokenReaderFn := func(ctx context.Context, addr, authToken string) (*authtokens.AuthToken, error) {
		switch authToken {
		case at.Token:
			return at, nil
		case unsupportedAt.Token:
			return unsupportedAt, nil
		}
		return nil, errors.New("test not found error")
	}

	readyNotificationCh := make(chan struct{})
	srv := daemon.NewTestServer(t, cmd)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := srv.Serve(
			t,
			daemon.WithBoundaryTokenReaderFunc(ctx, boundaryTokenReaderFn),
			daemon.WithReadyToServeNotificationCh(context.Background(), readyNotificationCh),
		)
		if err != nil {
			t.Error("Failed to serve daemon:", err)
		}
	}()
	t.Cleanup(wg.Wait)
	<-readyNotificationCh
	srv.AddKeyringToken(t, "address", "keyringtype", "tokenname", at.Id, boundaryTokenReaderFn)
	srv.AddKeyringToken(t, "address", "keyringtype", "unsupported", unsupportedAt.Id, boundaryTokenReaderFn)

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
			resp, r, apiErr, err := search(ctx, srv.BaseDotDir(), tc.fb)
			require.NoError(t, err)
			assert.NotNil(t, apiErr)
			assert.Contains(t, apiErr.Message, tc.apiErrContains)
			assert.NotNil(t, resp)
			assert.Nil(t, r)
		})
	}

	t.Run("empty response from list", func(t *testing.T) {
		resp, r, apiErr, err := search(ctx, srv.BaseDotDir(), filterBy{
			authTokenId: at.Id,
			resource:    "targets",
		})
		require.NoError(t, err)
		assert.NoError(t, err)
		assert.Nil(t, apiErr)
		assert.NotNil(t, resp)
		assert.NotNil(t, r)
		assert.EqualValues(t, &daemon.SearchResult{
			RefreshStatus: daemon.NotRefreshing,
		}, r)
	})

	t.Run("empty response from query", func(t *testing.T) {
		resp, r, apiErr, err := search(ctx, srv.BaseDotDir(), filterBy{
			authTokenId: at.Id,
			flagQuery:   "name='name'",
			resource:    "targets",
		})
		require.NoError(t, err)
		assert.NoError(t, err)
		assert.Nil(t, apiErr)
		assert.NotNil(t, resp)
		assert.NotNil(t, r)
		assert.EqualValues(t, r, &daemon.SearchResult{
			RefreshStatus: daemon.NotRefreshing,
		})
	})

	t.Run("unsupported boundary instance", func(t *testing.T) {
		srv.AddUnsupportedCachingData(t, unsupportedAt, boundaryTokenReaderFn)
		resp, r, apiErr, err := search(ctx, srv.BaseDotDir(), filterBy{
			authTokenId: unsupportedAt.Id,
			resource:    "targets",
		})
		assert.NoError(t, err)
		require.NotNil(t, apiErr)
		assert.NotNil(t, resp)
		assert.Nil(t, r)

		assert.Contains(t, apiErr.Message, "doesn't support search")
	})

	srv.AddResources(t, at, []*aliases.Alias{
		{Id: "alt_1234567890", Value: "value1", DestinationId: "ttcp_1234567890"},
		{Id: "alt_0987654321", Name: "value2", DestinationId: "ttcp_0987654321"},
	}, []*targets.Target{
		{Id: "ttcp_1234567890", Name: "name1", Description: "description1"},
		{Id: "ttcp_0987654321", Name: "name2", Description: "description2"},
	}, []*sessions.Session{
		{Id: "sess_1234567890", TargetId: "ttcp_1234567890", Status: "pending"},
		{Id: "sess_0987654321", TargetId: "ttcp_0987654321", Status: "pending"},
	}, boundaryTokenReaderFn)

	t.Run("target response from list", func(t *testing.T) {
		resp, r, apiErr, err := search(ctx, srv.BaseDotDir(), filterBy{
			authTokenId: at.Id,
			resource:    "targets",
		})
		require.NoError(t, err)
		assert.Nil(t, apiErr)
		assert.NotNil(t, resp)
		assert.NotNil(t, r)
		assert.Len(t, r.Targets, 2)
	})
	t.Run("search for unsupported controller", func(t *testing.T) {
		resp, r, apiErr, err := search(ctx, srv.BaseDotDir(), filterBy{
			authTokenId: at.Id,
			resource:    "targets",
		})
		require.NoError(t, err)
		assert.NoError(t, err)
		assert.Nil(t, apiErr)
		assert.NotNil(t, resp)
		assert.NotNil(t, r)
		assert.Len(t, r.Targets, 2)
	})
	t.Run("full target response from query", func(t *testing.T) {
		resp, r, apiErr, err := search(ctx, srv.BaseDotDir(), filterBy{
			authTokenId: at.Id,
			flagQuery:   "id % 'ttcp'",
			resource:    "targets",
		})
		require.NoError(t, err)
		assert.NoError(t, err)
		assert.Nil(t, apiErr)
		assert.NotNil(t, resp)
		assert.NotNil(t, r)
		assert.Len(t, r.Targets, 2)
	})
	t.Run("partial target response from query", func(t *testing.T) {
		resp, r, apiErr, err := search(ctx, srv.BaseDotDir(), filterBy{
			authTokenId: at.Id,
			flagQuery:   "id % 'ttcp_1234567890'",
			resource:    "targets",
		})
		require.NoError(t, err)
		assert.NoError(t, err)
		assert.Nil(t, apiErr)
		assert.NotNil(t, resp)
		assert.NotNil(t, r)
		assert.Len(t, r.Sessions, 0)
		assert.Len(t, r.Targets, 1)
	})

	t.Run("full target response from filter", func(t *testing.T) {
		resp, r, apiErr, err := search(ctx, srv.BaseDotDir(), filterBy{
			authTokenId: at.Id,
			flagFilter:  `"/item/id" matches "ttcp"`,
			resource:    "targets",
		})
		require.NoError(t, err)
		assert.NoError(t, err)
		assert.Nil(t, apiErr)
		assert.NotNil(t, resp)
		assert.NotNil(t, r)
		assert.Len(t, r.Targets, 2)
	})
	t.Run("partial target response from filter", func(t *testing.T) {
		resp, r, apiErr, err := search(ctx, srv.BaseDotDir(), filterBy{
			authTokenId: at.Id,
			flagFilter:  `"/item/id" matches "ttcp_1234567890"`,
			resource:    "targets",
		})
		require.NoError(t, err)
		assert.NoError(t, err)
		assert.Nil(t, apiErr)
		assert.NotNil(t, resp)
		assert.NotNil(t, r)
		assert.Len(t, r.Sessions, 0)
		assert.Len(t, r.Targets, 1)
	})

	t.Run("session response from list", func(t *testing.T) {
		resp, r, apiErr, err := search(ctx, srv.BaseDotDir(), filterBy{
			authTokenId: at.Id,
			resource:    "sessions",
		})
		require.NoError(t, err)
		assert.NoError(t, err)
		assert.Nil(t, apiErr)
		assert.NotNil(t, resp)
		assert.NotNil(t, r)
		assert.Len(t, r.Targets, 0)
		assert.Len(t, r.Sessions, 2)
	})
	t.Run("full session response from query", func(t *testing.T) {
		resp, r, apiErr, err := search(ctx, srv.BaseDotDir(), filterBy{
			authTokenId: at.Id,
			flagQuery:   "id % 'sess'",
			resource:    "sessions",
		})
		require.NoError(t, err)
		assert.NoError(t, err)
		assert.Nil(t, apiErr)
		assert.NotNil(t, resp)
		assert.NotNil(t, r)
		assert.Len(t, r.Sessions, 2)
	})
	t.Run("partial session response from query", func(t *testing.T) {
		resp, r, apiErr, err := search(ctx, srv.BaseDotDir(), filterBy{
			authTokenId: at.Id,
			flagQuery:   "id % 'sess_1234567890'",
			resource:    "sessions",
		})
		require.NoError(t, err)
		assert.NoError(t, err)
		assert.Nil(t, apiErr)
		assert.NotNil(t, resp)
		assert.NotNil(t, r)
		assert.Len(t, r.Sessions, 1)
	})
	t.Run("full session response from filter", func(t *testing.T) {
		resp, r, apiErr, err := search(ctx, srv.BaseDotDir(), filterBy{
			authTokenId: at.Id,
			flagFilter:  `"/item/id" matches "sess"`,
			resource:    "sessions",
		})
		require.NoError(t, err)
		assert.NoError(t, err)
		assert.Nil(t, apiErr)
		assert.NotNil(t, resp)
		assert.NotNil(t, r)
		assert.Len(t, r.Sessions, 2)
	})
	t.Run("partial session response from filter", func(t *testing.T) {
		resp, r, apiErr, err := search(ctx, srv.BaseDotDir(), filterBy{
			authTokenId: at.Id,
			flagFilter:  `"/item/id" matches "sess_1234567890"`,
			resource:    "sessions",
		})
		require.NoError(t, err)
		assert.NoError(t, err)
		assert.Nil(t, apiErr)
		assert.NotNil(t, resp)
		assert.NotNil(t, r)
		assert.Len(t, r.Sessions, 1)
	})
}
