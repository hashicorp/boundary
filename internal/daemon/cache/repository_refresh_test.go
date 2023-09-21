// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/daemon/worker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/targets/tcp"
)

// noopRetrievalFn is a function that satisfies the Refresh's With*RetrievalFn
// and returns nil, nil always
func noopRetrievalFn[T any](context.Context, string, string) ([]T, error) {
	return nil, nil
}

func TestRefresh(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx)
	require.NoError(t, err)

	internalAuthTokenFn := testAuthTokenLookup
	atLookupFunc := func(k, t string) *authtokens.AuthToken {
		return internalAuthTokenFn(k, t)
	}
	r, err := NewRepository(ctx, s, atLookupFunc)
	require.NoError(t, err)

	boundaryAddr := "address"
	p := KeyringToken{
		KeyringType: "keyring",
		TokenName:   "token",
	}
	at := testAuthTokenLookup(p.KeyringType, p.TokenName)
	p.AuthTokenId = at.Id
	require.NoError(t, r.AddKeyringToken(ctx, boundaryAddr, p))
	u := &user{Id: at.UserId, Address: boundaryAddr}

	t.Run("set targets", func(t *testing.T) {
		retTargets := []*targets.Target{
			target("1"),
			target("2"),
			target("3"),
		}
		assert.NoError(t, r.Refresh(ctx,
			WithSessionRetrievalFunc(noopRetrievalFn[*sessions.Session]),
			WithTargetRetrievalFunc(func(ctx context.Context, addr, token string) ([]*targets.Target, error) {
				require.Equal(t, boundaryAddr, addr)
				require.Equal(t, at.Token, token)
				return retTargets, nil
			})))

		cachedTargets, err := r.ListTargets(ctx, at.Id)
		assert.NoError(t, err)
		assert.ElementsMatch(t, retTargets, cachedTargets)

		t.Run("empty response clears it out", func(t *testing.T) {
			assert.NoError(t, r.Refresh(ctx,
				WithSessionRetrievalFunc(noopRetrievalFn[*sessions.Session]),
				WithTargetRetrievalFunc(func(ctx context.Context, addr, token string) ([]*targets.Target, error) {
					require.Equal(t, boundaryAddr, addr)
					require.Equal(t, at.Token, token)
					return nil, nil
				})))

			cachedTargets, err := r.ListTargets(ctx, at.Id)
			assert.NoError(t, err)
			assert.Empty(t, cachedTargets)
		})
	})

	t.Run("set sessions", func(t *testing.T) {
		retSess := []*sessions.Session{
			session("1"),
			session("2"),
			session("3"),
		}
		assert.NoError(t, r.Refresh(ctx,
			WithTargetRetrievalFunc(noopRetrievalFn[*targets.Target]),
			WithSessionRetrievalFunc(func(ctx context.Context, addr, token string) ([]*sessions.Session, error) {
				require.Equal(t, boundaryAddr, addr)
				require.Equal(t, at.Token, token)
				return retSess, nil
			})))

		cachedSessions, err := r.ListSessions(ctx, at.Id)
		assert.NoError(t, err)
		assert.ElementsMatch(t, retSess, cachedSessions)

		t.Run("empty response clears it out", func(t *testing.T) {
			assert.NoError(t, r.Refresh(ctx,
				WithTargetRetrievalFunc(noopRetrievalFn[*targets.Target]),
				WithSessionRetrievalFunc(func(ctx context.Context, addr, token string) ([]*sessions.Session, error) {
					require.Equal(t, boundaryAddr, addr)
					require.Equal(t, at.Token, token)
					return nil, nil
				})))

			cachedTargets, err := r.ListSessions(ctx, at.Id)
			assert.NoError(t, err)
			assert.Empty(t, cachedTargets)
		})
	})

	t.Run("error propogates up", func(t *testing.T) {
		innerErr := errors.New("test error")
		err := r.Refresh(ctx,
			WithSessionRetrievalFunc(noopRetrievalFn[*sessions.Session]),
			WithTargetRetrievalFunc(func(ctx context.Context, addr, token string) ([]*targets.Target, error) {
				require.Equal(t, boundaryAddr, addr)
				require.Equal(t, at.Token, token)
				return nil, innerErr
			}))
		assert.ErrorContains(t, err, innerErr.Error())
		err = r.Refresh(ctx,
			WithTargetRetrievalFunc(noopRetrievalFn[*targets.Target]),
			WithSessionRetrievalFunc(func(ctx context.Context, addr, token string) ([]*sessions.Session, error) {
				require.Equal(t, boundaryAddr, addr)
				require.Equal(t, at.Token, token)
				return nil, innerErr
			}))
		assert.ErrorContains(t, err, innerErr.Error())
	})

	t.Run("tokens that are no longer in the ring is deleted", func(t *testing.T) {
		internalAuthTokenFn = func(k, t string) *authtokens.AuthToken {
			return nil
		}
		t.Cleanup(func() {
			internalAuthTokenFn = testAuthTokenLookup
			assert.NoError(t, r.AddKeyringToken(ctx, boundaryAddr, p))
		})

		ps, err := r.listTokens(ctx, u)
		require.NoError(t, err)
		assert.Len(t, ps, 1)

		us, err := r.listUsers(ctx)
		require.NoError(t, err)
		assert.Len(t, us, 1)

		r.Refresh(ctx,
			WithSessionRetrievalFunc(noopRetrievalFn[*sessions.Session]),
			WithTargetRetrievalFunc(noopRetrievalFn[*targets.Target]))

		ps, err = r.listTokens(ctx, u)
		require.NoError(t, err)
		assert.Empty(t, ps)

		// And since the last token was deleted, the user also was deleted
		us, err = r.listUsers(ctx)
		require.NoError(t, err)
		assert.Empty(t, us)
	})
}

func TestDefaultTargetRetrievalFunc(t *testing.T) {
	tc := controller.NewTestController(t, nil)
	tc.Client().SetToken(tc.Token().Token)
	tarClient := targets.NewClient(tc.Client())

	tar1, err := tarClient.Create(tc.Context(), "tcp", "p_1234567890", targets.WithName("tar1"), targets.WithTcpTargetDefaultPort(1))
	require.NoError(t, err)
	require.NotNil(t, tar1)
	tar2, err := tarClient.Create(tc.Context(), "tcp", "p_1234567890", targets.WithName("tar2"), targets.WithTcpTargetDefaultPort(2))
	require.NoError(t, err)
	require.NotNil(t, tar2)

	got, err := defaultTargetFunc(tc.Context(), tc.ApiAddrs()[0], tc.Token().Token)
	assert.NoError(t, err)
	assert.Contains(t, got, tar1.Item)
	assert.Contains(t, got, tar2.Item)
}

func TestDefaultSessionRetrievalFunc(t *testing.T) {
	tc := controller.NewTestController(t, nil)
	tc.Client().SetToken(tc.Token().Token)
	tarClient := targets.NewClient(tc.Client())
	_ = worker.NewTestWorker(t, &worker.TestWorkerOpts{
		InitialUpstreams: tc.ClusterAddrs(),
		WorkerAuthKms:    tc.Config().WorkerAuthKms,
	})

	tar1, err := tarClient.Create(tc.Context(), "tcp", "p_1234567890", targets.WithName("tar1"), targets.WithTcpTargetDefaultPort(1), targets.WithAddress("address"))
	require.NoError(t, err)
	require.NotNil(t, tar1)
	_, err = tarClient.AuthorizeSession(tc.Context(), tar1.Item.Id)
	assert.NoError(t, err)

	got, err := defaultSessionFunc(tc.Context(), tc.ApiAddrs()[0], tc.Token().Token)
	assert.NoError(t, err)
	assert.Len(t, got, 1)
}

func target(suffix string) *targets.Target {
	return &targets.Target{
		Id:          fmt.Sprintf("target_%s", suffix),
		Name:        fmt.Sprintf("name_%s", suffix),
		Description: fmt.Sprintf("description_%s", suffix),
		Address:     fmt.Sprintf("address_%s", suffix),
		Type:        "tcp",
	}
}

func session(suffix string) *sessions.Session {
	return &sessions.Session{
		Id:   fmt.Sprintf("session_%s", suffix),
		Type: "tcp",
	}
}
