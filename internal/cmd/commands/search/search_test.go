// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package search

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/commands/daemon"
	"github.com/hashicorp/boundary/internal/daemon/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testCommander struct {
	t *testing.T
	p *cache.Persona
}

func (r *testCommander) keyring() string {
	return r.p.KeyringType
}

func (r *testCommander) tokenName() string {
	return r.p.TokenName
}

func (r *testCommander) Client(opt ...base.Option) (*api.Client, error) {
	client, err := api.NewClient(nil)
	require.NoError(r.t, err)
	client.SetAddr(r.p.BoundaryAddr)
	return client, nil
}

func (r *testCommander) DiscoverKeyringTokenInfo() (string, string, error) {
	return r.keyring(), r.tokenName(), nil
}

func (r *testCommander) ReadTokenFromKeyring(k, a string) *authtokens.AuthToken {
	return &authtokens.AuthToken{
		Id:           r.p.AuthTokenId,
		AuthMethodId: "test_auth_method",
		Token:        fmt.Sprintf("%s_restofthetoken", r.p.AuthTokenId),
		UserId:       r.p.UserId,
	}
}

func TestSearch(t *testing.T) {
	ctx := context.Background()
	cmd := &testCommander{t: t, p: &cache.Persona{UserId: "u_1234567890", BoundaryAddr: "http://someaddr", TokenName: "token1", KeyringType: "keyring"}}

	srv := daemon.NewTestServer(t, cmd)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv.Serve(t)
	}()
	// Give the store some time to get initialized
	time.Sleep(100 * time.Millisecond)

	errorCases := []struct {
		name           string
		fb             filterBy
		apiErrContains string
	}{
		{
			name: "no resource",
			fb: filterBy{
				boundaryAddr: cmd.p.BoundaryAddr,
				keyringType:  cmd.keyring(),
				tokenName:    cmd.tokenName(),
				flagQuery:    "name=name",
			},
			apiErrContains: "resource is a required field but was empty",
		},
		{
			name: "bad resource",
			fb: filterBy{
				boundaryAddr: cmd.p.BoundaryAddr,
				keyringType:  cmd.keyring(),
				tokenName:    cmd.tokenName(),
				flagQuery:    "name=name",
				resource:     "hosts",
			},
			apiErrContains: "doesn't support \"hosts\" resource",
		},
		{
			name: "no boundary addr",
			fb: filterBy{
				keyringType: cmd.keyring(),
				tokenName:   cmd.tokenName(),
				flagQuery:   "name=name",
				resource:    "targets",
			},
			apiErrContains: "boundary_addr is a required field but was empty",
		},
		{
			name: "no keyring type",
			fb: filterBy{
				boundaryAddr: cmd.p.BoundaryAddr,
				tokenName:    cmd.tokenName(),
				flagQuery:    "name=name",
				resource:     "targets",
			},
			apiErrContains: "keyring_type is a required field but was empty",
		},
		{
			name: "no token name",
			fb: filterBy{
				boundaryAddr: cmd.p.BoundaryAddr,
				keyringType:  cmd.keyring(),
				flagQuery:    "name=name",
				resource:     "targets",
			},
			apiErrContains: "token_name is a required field but was empty",
		},
		{
			name: "unknown persona",
			fb: filterBy{
				boundaryAddr: "an unknown address",
				keyringType:  "unrecognized",
				tokenName:    "unrecognized",
				flagQuery:    "description % tar",
				resource:     "targets",
			},
			apiErrContains: "Forbidden",
		},
		{
			name: "query on unsupported column",
			fb: filterBy{
				boundaryAddr: cmd.p.BoundaryAddr,
				keyringType:  cmd.keyring(),
				tokenName:    cmd.tokenName(),
				flagQuery:    "item % tar",
				resource:     "targets",
			},
			apiErrContains: "invalid column \"item\"",
		},
	}

	for _, tc := range errorCases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := search(ctx, srv.BaseSocketDir(), tc.fb)
			require.NoError(t, err)
			r := daemon.SearchResult{}
			apiErr, err := resp.Decode(&r)
			assert.NoError(t, err)
			assert.NotNil(t, apiErr)
			assert.Contains(t, apiErr.Message, tc.apiErrContains)
		})
	}

	t.Run("empty response from list", func(t *testing.T) {
		resp, err := search(ctx, srv.BaseSocketDir(), filterBy{
			boundaryAddr: cmd.p.BoundaryAddr,
			keyringType:  cmd.keyring(),
			tokenName:    cmd.tokenName(),
			resource:     "targets",
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
		resp, err := search(ctx, srv.BaseSocketDir(), filterBy{
			boundaryAddr: cmd.p.BoundaryAddr,
			keyringType:  cmd.keyring(),
			tokenName:    cmd.tokenName(),
			flagQuery:    "name=name",
			resource:     "targets",
		})
		require.NoError(t, err)
		r := daemon.SearchResult{}
		apiErr, err := resp.Decode(&r)
		assert.NoError(t, err)
		assert.Nil(t, apiErr)
		assert.NotNil(t, r)
		assert.EqualValues(t, r, daemon.SearchResult{})
	})

	srv.AddTargets(t, cmd.p.BoundaryAddr, cmd.ReadTokenFromKeyring(cmd.keyring(), cmd.tokenName()).Token, []*targets.Target{
		{Id: "ttcp_1234567890", Name: "name1", Description: "description1"},
		{Id: "ttcp_0987654321", Name: "name2", Description: "description2"},
	})

	t.Run("response from list", func(t *testing.T) {
		resp, err := search(ctx, srv.BaseSocketDir(), filterBy{
			boundaryAddr: cmd.p.BoundaryAddr,
			keyringType:  cmd.keyring(),
			tokenName:    cmd.tokenName(),
			resource:     "targets",
		})
		require.NoError(t, err)
		r := daemon.SearchResult{}
		apiErr, err := resp.Decode(&r)
		assert.NoError(t, err)
		assert.Nil(t, apiErr)
		assert.NotNil(t, r)
		assert.Len(t, r.Targets, 2)
	})
	t.Run("full response from query", func(t *testing.T) {
		resp, err := search(ctx, srv.BaseSocketDir(), filterBy{
			boundaryAddr: cmd.p.BoundaryAddr,
			keyringType:  cmd.keyring(),
			tokenName:    cmd.tokenName(),
			flagQuery:    "id % ttcp",
			resource:     "targets",
		})
		require.NoError(t, err)
		r := daemon.SearchResult{}
		apiErr, err := resp.Decode(&r)
		assert.NoError(t, err)
		assert.Nil(t, apiErr)
		assert.NotNil(t, r)
		assert.Len(t, r.Targets, 2)
	})
	t.Run("partial response from query", func(t *testing.T) {
		resp, err := search(ctx, srv.BaseSocketDir(), filterBy{
			boundaryAddr: cmd.p.BoundaryAddr,
			keyringType:  cmd.keyring(),
			tokenName:    cmd.tokenName(),
			flagQuery:    "id % ttcp_1234567890",
			resource:     "targets",
		})
		require.NoError(t, err)
		r := daemon.SearchResult{}
		apiErr, err := resp.Decode(&r)
		assert.NoError(t, err)
		assert.Nil(t, apiErr)
		assert.NotNil(t, r)
		assert.Len(t, r.Targets, 1)
	})
}
