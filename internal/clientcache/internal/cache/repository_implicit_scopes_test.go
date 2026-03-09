// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"sync"
	"testing"

	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/api/targets"
	cachedb "github.com/hashicorp/boundary/internal/clientcache/internal/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
)

func TestRepository_ImplicitScopes(t *testing.T) {
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

	var expectedScopes []*scopes.Scope

	ts := []*targets.Target{
		target("1"),
		target("2"),
		target("3"),
	}
	require.NoError(t, r.refreshTargets(ctx, u1, map[AuthToken]string{{Id: "id"}: "something"},
		WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc(t, [][]*targets.Target{ts}, [][]string{nil})))))

	for _, t := range ts {
		expectedScopes = append(expectedScopes, &scopes.Scope{
			Id: t.ScopeId,
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

	expectedScopes = append(expectedScopes, &scopes.Scope{
		Id: ss[0].ScopeId,
	})

	t.Run("wrong user gets no implicit scopes", func(t *testing.T) {
		l, err := r.ListImplicitScopes(ctx, kt2.AuthTokenId)
		require.NoError(t, err)
		assert.Empty(t, l.ImplicitScopes)
	})
	t.Run("correct token gets implicit scopes from listing", func(t *testing.T) {
		l, err := r.ListImplicitScopes(ctx, kt1.AuthTokenId)
		require.NoError(t, err)
		assert.Len(t, l.ImplicitScopes, len(expectedScopes))
		assert.ElementsMatch(t, l.ImplicitScopes, expectedScopes)
	})
	t.Run("querying returns error", func(t *testing.T) {
		_, err := r.QueryImplicitScopes(ctx, kt1.AuthTokenId, "anything")
		require.Error(t, err)
	})
}
