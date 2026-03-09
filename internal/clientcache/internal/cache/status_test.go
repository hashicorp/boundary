// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api/aliases"
	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/api/targets"
	cachedb "github.com/hashicorp/boundary/internal/clientcache/internal/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewStatusService(t *testing.T) {
	ctx := context.Background()

	t.Run("nil repo", func(t *testing.T) {
		s, err := NewStatusService(ctx, nil)
		assert.Error(t, err)
		assert.Nil(t, s)
	})

	t.Run("success", func(t *testing.T) {
		s, err := cachedb.Open(ctx)
		require.NoError(t, err)
		r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(nil), sliceBasedAuthTokenBoundaryReader(nil))
		require.NoError(t, err)

		service, err := NewStatusService(ctx, r)
		assert.NoError(t, err)
		assert.NotNil(t, service)
	})
}

func TestStatus(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)

	boundaryAddr := "address"
	u1 := &user{Id: "u1", Address: boundaryAddr}
	at1a := &authtokens.AuthToken{
		Id:             "at_1a",
		Token:          "at_1a_token",
		UserId:         u1.Id,
		ExpirationTime: time.Now().Add(time.Minute),
	}
	at1b := &authtokens.AuthToken{
		Id:             "at_1b",
		Token:          "at_1b_token",
		UserId:         u1.Id,
		ExpirationTime: time.Now().Add(time.Minute),
	}

	u2 := &user{Id: "u2", Address: boundaryAddr}
	at2 := &authtokens.AuthToken{
		Id:             "at_2",
		Token:          "at_2_token",
		UserId:         u2.Id,
		ExpirationTime: time.Now().Add(time.Minute),
	}

	boundaryAuthTokens := []*authtokens.AuthToken{at1a, at1b, at2}
	atMap := map[ringToken]*authtokens.AuthToken{
		{k: "default", t: "default"}:   at1a,
		{k: "default2", t: "default2"}: at1b,
	}
	r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(boundaryAuthTokens))
	require.NoError(t, err)

	ss, err := NewStatusService(ctx, r)
	require.NoError(t, err)

	t.Run("empty status", func(t *testing.T) {
		got, err := ss.Status(ctx)
		assert.NoError(t, err)
		assert.Equal(t, &Status{}, got)
	})

	require.NoError(t, r.AddKeyringToken(ctx, boundaryAddr, KeyringToken{
		KeyringType: "default",
		TokenName:   "default",
		AuthTokenId: at1a.Id,
	}))
	require.NoError(t, r.AddKeyringToken(ctx, boundaryAddr, KeyringToken{
		KeyringType: "default2",
		TokenName:   "default2",
		AuthTokenId: at1b.Id,
	}))
	require.NoError(t, r.AddRawToken(ctx, boundaryAddr, at1b.Token))
	require.NoError(t, r.AddRawToken(ctx, boundaryAddr, at2.Token))

	t.Run("users with no resources", func(t *testing.T) {
		got, err := ss.Status(ctx)
		assert.NoError(t, err)
		assert.Equal(t, &Status{
			Users: []UserStatus{
				{
					Id: u1.Id,
					BoundaryStatus: BoundaryStatus{
						Address:          u1.Address,
						CachingSupported: UnknownCacheSupport,
					},
					AuthTokens: []AuthTokenStatus{
						{
							Id:                    at1a.Id,
							KeyringReferences:     1,
							KeyringlessReferences: 0,
						},
						{
							Id:                    at1b.Id,
							KeyringReferences:     1,
							KeyringlessReferences: 1,
						},
					},
					Resources: []ResourceStatus{
						{
							Name:  string(resolvableAliasResourceType),
							Count: 0,
						},
						{
							Name:  string(targetResourceType),
							Count: 0,
						},
						{
							Name:  string(sessionResourceType),
							Count: 0,
						},
					},
				},
				{
					Id: u2.Id,
					BoundaryStatus: BoundaryStatus{
						Address:          u2.Address,
						CachingSupported: UnknownCacheSupport,
					},
					AuthTokens: []AuthTokenStatus{
						{
							Id:                    at2.Id,
							KeyringReferences:     0,
							KeyringlessReferences: 1,
						},
					},
					Resources: []ResourceStatus{
						{
							Name:  string(resolvableAliasResourceType),
							Count: 0,
						},
						{
							Name:  string(targetResourceType),
							Count: 0,
						},
						{
							Name:  string(sessionResourceType),
							Count: 0,
						},
					},
				},
			},
		}, got)
	})

	t.Run("users with errors", func(t *testing.T) {
		require.NoError(t, r.saveError(ctx, u1, targetResourceType, fmt.Errorf("test error")))

		got, err := ss.Status(ctx)
		assert.NoError(t, err)

		lastErr := got.Users[0].Resources[1].LastError
		assert.NotNil(t, lastErr)
		assert.Equal(t, "test error", lastErr.Error)
		assert.NotZero(t, lastErr.LastReturned)
	})

	t.Run("users with resources", func(t *testing.T) {
		require.NoError(t, r.saveError(ctx, u1, targetResourceType, fmt.Errorf("test error")))

		ts := []*targets.Target{
			target("1"),
			target("2"),
			target("3"),
			target("4"),
		}
		err = r.refreshTargets(ctx, u1, map[AuthToken]string{{Id: "id"}: "something"},
			WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc(t, [][]*targets.Target{ts}, [][]string{nil}))))
		require.NoError(t, err)

		err = r.refreshTargets(ctx, u2, map[AuthToken]string{{Id: "id"}: "something"},
			WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc(t, [][]*targets.Target{ts[:2]}, [][]string{nil}))))
		require.NoError(t, err)

		sess := []*sessions.Session{
			session("1"),
			session("2"),
			session("3"),
		}
		err := r.refreshSessions(ctx, u1, map[AuthToken]string{{Id: "id"}: "something"},
			WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testStaticResourceRetrievalFunc(t, [][]*sessions.Session{sess}, [][]string{nil}))))
		require.NoError(t, err)

		als := []*aliases.Alias{
			alias("1"),
			alias("2"),
			alias("3"),
		}
		err = r.refreshResolvableAliases(ctx, u1, map[AuthToken]string{{Id: "id"}: "something"},
			WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testStaticResourceRetrievalFuncForId(t, [][]*aliases.Alias{als}, [][]string{nil}))))
		require.NoError(t, err)

		got, err := ss.Status(ctx)
		assert.NoError(t, err)

		assert.Len(t, got.Users, 2)
		assert.Equal(t, Map(got.Users, func(i UserStatus) string {
			return i.Id
		}), []string{"u1", "u2"})

		// User 1 status
		assert.Equal(t, Map(got.Users[0].AuthTokens, func(i AuthTokenStatus) string {
			return i.Id
		}), []string{"at_1a", "at_1b"})

		assert.Equal(t, Map(got.Users[0].Resources, func(i ResourceStatus) string {
			return i.Name
		}), []string{string(resolvableAliasResourceType), string(targetResourceType), string(sessionResourceType)})

		assert.Equal(t, Map(got.Users[0].Resources, func(i ResourceStatus) int {
			return i.Count
		}), []int{3, 4, 3})

		assert.Equal(t, Map(got.Users[0].Resources, func(i ResourceStatus) bool {
			return i.LastError == nil
		}), []bool{true, false, true}, "expected an error for target resource and none for other resources")

		assert.Equal(t, Map(got.Users[0].Resources, func(i ResourceStatus) bool {
			return i.RefreshToken == nil
		}), []bool{false, false, false})

		// User 2 status
		assert.Equal(t, Map(got.Users[1].AuthTokens, func(i AuthTokenStatus) string {
			return i.Id
		}), []string{"at_2"})

		assert.Equal(t, Map(got.Users[1].Resources, func(i ResourceStatus) string {
			return i.Name
		}), []string{string(resolvableAliasResourceType), string(targetResourceType), string(sessionResourceType)})

		assert.Equal(t, Map(got.Users[1].Resources, func(i ResourceStatus) int {
			return i.Count
		}), []int{0, 2, 0})

		assert.Equal(t, Map(got.Users[1].Resources, func(i ResourceStatus) bool {
			return i.LastError == nil
		}), []bool{true, true, true})

		assert.Equal(t, Map(got.Users[1].Resources, func(i ResourceStatus) bool {
			return i.RefreshToken == nil
		}), []bool{true, false, true}, "targets expected to have a refresh token and others aren't")
	})
}

// Map maps a slice of one type into a slice of another using the provided map
// function
func Map[T, U any](in []T, f func(T) U) []U {
	var ret []U
	for _, t := range in {
		ret = append(ret, f(t))
	}
	return ret
}

func TestStatus_unsupported(t *testing.T) {
	ctx := context.Background()
	s, err := cachedb.Open(ctx)
	require.NoError(t, err)

	boundaryAddr := "address"
	u1 := &user{Id: "u1", Address: boundaryAddr}
	at1 := &authtokens.AuthToken{
		Id:             "at_1a",
		Token:          "at_1a_token",
		UserId:         u1.Id,
		ExpirationTime: time.Now().Add(time.Minute),
	}

	boundaryAuthTokens := []*authtokens.AuthToken{at1}
	atMap := map[ringToken]*authtokens.AuthToken{
		{k: "default", t: "default"}: at1,
	}
	r, err := NewRepository(ctx, s, &sync.Map{}, mapBasedAuthTokenKeyringLookup(atMap), sliceBasedAuthTokenBoundaryReader(boundaryAuthTokens))
	require.NoError(t, err)

	ss, err := NewStatusService(ctx, r)
	require.NoError(t, err)

	require.NoError(t, r.AddKeyringToken(ctx, boundaryAddr, KeyringToken{
		KeyringType: "default",
		TokenName:   "default",
		AuthTokenId: at1.Id,
	}))

	err = r.refreshResolvableAliases(ctx, u1, map[AuthToken]string{{Id: "id"}: "something"},
		WithAliasRetrievalFunc(testResolvableAliasStaticResourceRetrievalFunc(testNoRefreshRetrievalFuncForId[*aliases.Alias](t))))
	require.ErrorIs(t, err, ErrRefreshNotSupported)

	err = r.refreshTargets(ctx, u1, map[AuthToken]string{{Id: "id"}: "something"},
		WithTargetRetrievalFunc(testTargetStaticResourceRetrievalFunc(testNoRefreshRetrievalFunc[*targets.Target](t))))
	require.ErrorIs(t, err, ErrRefreshNotSupported)

	err = r.refreshSessions(ctx, u1, map[AuthToken]string{{Id: "id"}: "something"},
		WithSessionRetrievalFunc(testSessionStaticResourceRetrievalFunc(testNoRefreshRetrievalFunc[*sessions.Session](t))))
	require.ErrorIs(t, err, ErrRefreshNotSupported)

	got, err := ss.Status(ctx)
	assert.NoError(t, err)

	assert.Len(t, got.Users, 1)
	assert.Greater(t, got.Users[0].BoundaryStatus.LastSupportCheck, time.Duration(0))
	assert.LessOrEqual(t, got.Users[0].BoundaryStatus.LastSupportCheck, time.Second)
	got.Users[0].BoundaryStatus.LastSupportCheck = 0

	assert.Equal(t, got.Users, []UserStatus{
		{
			Id: u1.Id,
			BoundaryStatus: BoundaryStatus{
				Address:          u1.Address,
				CachingSupported: NotSupportedCacheSupport,
			},
			AuthTokens: []AuthTokenStatus{
				{
					Id:                at1.Id,
					KeyringReferences: 1,
				},
			},
			Resources: []ResourceStatus{
				{
					Name:  string(resolvableAliasResourceType),
					Count: 0,
				},
				{
					Name:  string(targetResourceType),
					Count: 0,
				},
				{
					Name:  string(sessionResourceType),
					Count: 0,
				},
			},
		},
	})
}
