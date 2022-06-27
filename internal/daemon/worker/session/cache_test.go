package session

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/targets"

	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/stretchr/testify/require"
)

//func TestNewCache(t *testing.T) {
//	c := controller.NewTestController(t, nil)
//
//	ctx := context.Background()
//	cc, err := grpc.DialContext(ctx, c.ClusterAddrs()[0])
//	require.NoError(t, err)
//	cache := NewCache(cc)
//	_ = cache
//}

func TestWorkerSetCloseTimeForResponse(t *testing.T) {
	cases := []struct {
		name             string
		sessionCloseInfo map[string][]*pbs.CloseConnectionResponseData
		sessionInfoMap   func() *sync.Map
		expected         []string
		expectedClosed   map[string]struct{}
		expectedErr      []error
	}{
		{
			name: "basic",
			sessionCloseInfo: map[string][]*pbs.CloseConnectionResponseData{
				"one": {
					{ConnectionId: "foo", Status: pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED},
				},
				"two": {
					{ConnectionId: "bar", Status: pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED},
				},
			},
			sessionInfoMap: func() *sync.Map {
				m := new(sync.Map)
				m.Store("one", &Session{
					resp: &pbs.LookupSessionResponse{Authorization: &targets.SessionAuthorizationData{
						SessionId: "one",
					}},
					connInfoMap: map[string]*ConnInfo{
						"foo": {Id: "foo"},
					},
				})
				m.Store("two", &Session{
					resp: &pbs.LookupSessionResponse{Authorization: &targets.SessionAuthorizationData{
						SessionId: "two",
					}},
					connInfoMap: map[string]*ConnInfo{
						"bar": {Id: "bar"},
					},
				})
				m.Store("three", &Session{
					resp: &pbs.LookupSessionResponse{Authorization: &targets.SessionAuthorizationData{
						SessionId: "three",
					}},
					connInfoMap: map[string]*ConnInfo{
						"baz": {Id: "baz"},
					},
				})

				return m
			},
			expected: []string{"foo", "bar"},
			expectedClosed: map[string]struct{}{
				"foo": {},
				"bar": {},
			},
		},
		{
			name: "not closed",
			sessionCloseInfo: map[string][]*pbs.CloseConnectionResponseData{
				"one": {
					{ConnectionId: "foo", Status: pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED},
				},
				"two": {
					{ConnectionId: "bar", Status: pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CONNECTED},
				},
			},
			sessionInfoMap: func() *sync.Map {
				m := new(sync.Map)
				m.Store("one", &Session{
					resp: &pbs.LookupSessionResponse{Authorization: &targets.SessionAuthorizationData{
						SessionId: "one",
					}},
					connInfoMap: map[string]*ConnInfo{
						"foo": {Id: "foo"},
					},
				})
				m.Store("two", &Session{
					resp: &pbs.LookupSessionResponse{Authorization: &targets.SessionAuthorizationData{
						SessionId: "two",
					}},
					connInfoMap: map[string]*ConnInfo{
						"bar": {Id: "bar"},
					},
				})

				return m
			},
			expected: []string{"foo"},
			expectedClosed: map[string]struct{}{
				"foo": {},
			},
		},
		{
			name: "missing session",
			sessionCloseInfo: map[string][]*pbs.CloseConnectionResponseData{
				"one": {
					{ConnectionId: "foo", Status: pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED},
				},
				"two": {
					{ConnectionId: "bar", Status: pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED},
				},
			},
			sessionInfoMap: func() *sync.Map {
				m := new(sync.Map)
				m.Store("one", &Session{
					resp: &pbs.LookupSessionResponse{Authorization: &targets.SessionAuthorizationData{
						SessionId: "one",
					}},
					connInfoMap: map[string]*ConnInfo{
						"foo": {Id: "foo"},
					},
				})

				return m
			},
			expected: []string{"foo"},
			expectedClosed: map[string]struct{}{
				"foo": {},
			},
			expectedErr: []error{
				errors.New(`could not find session ID "two" in local state after closing connections`),
			},
		},
		{
			name: "missing connection",
			sessionCloseInfo: map[string][]*pbs.CloseConnectionResponseData{
				"one": {
					{ConnectionId: "foo", Status: pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED},
				},
				"two": {
					{ConnectionId: "bar", Status: pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED},
				},
			},
			sessionInfoMap: func() *sync.Map {
				m := new(sync.Map)
				m.Store("one", &Session{
					resp: &pbs.LookupSessionResponse{Authorization: &targets.SessionAuthorizationData{
						SessionId: "one",
					}},
					connInfoMap: map[string]*ConnInfo{
						"foo": {Id: "foo"},
					},
				})
				m.Store("two", &Session{
					resp: &pbs.LookupSessionResponse{Authorization: &targets.SessionAuthorizationData{
						SessionId: "two",
					}},
				})

				return m
			},
			expected: []string{"foo"},
			expectedClosed: map[string]struct{}{
				"foo": {},
			},
			expectedErr: []error{
				errors.New(`could not find connection ID "bar" for session ID "two" in local state`),
			},
		},
		{
			name:             "empty",
			sessionCloseInfo: make(map[string][]*pbs.CloseConnectionResponseData),
			sessionInfoMap: func() *sync.Map {
				m := new(sync.Map)
				m.Store("one", &Session{
					resp: &pbs.LookupSessionResponse{Authorization: &targets.SessionAuthorizationData{
						SessionId: "one",
					}},
					connInfoMap: map[string]*ConnInfo{
						"foo": {Id: "foo"},
					},
				})

				return m
			},
			expected:       []string{},
			expectedClosed: map[string]struct{}{},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			cache := NewCache(nil)
			cache.sessionMap = tc.sessionInfoMap()
			actual, actualErr := setCloseTimeForResponse(cache, tc.sessionCloseInfo)

			// Assert all close times were set
			cache.ForEachSession(func(value *Session) bool {
				t.Helper()
				for _, ci := range value.GetConnections() {
					if _, ok := tc.expectedClosed[ci.Id]; ok {
						require.NotEqual(time.Time{}, ci.CloseTime)
					} else {
						require.Equal(time.Time{}, ci.CloseTime)
					}
				}

				return true
			})

			// Assert return values
			require.ElementsMatch(tc.expected, actual)
			require.ElementsMatch(tc.expectedErr, actualErr)
		})
	}
}
