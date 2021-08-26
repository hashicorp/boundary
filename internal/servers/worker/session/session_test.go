package session

import (
	"errors"
	"sync"
	"testing"
	"time"

	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/stretchr/testify/require"
)

func TestWorkerMakeCloseConnectionRequest(t *testing.T) {
	require := require.New(t)
	in := map[string]string{"foo": "one", "bar": "two"}
	expected := &pbs.CloseConnectionRequest{
		CloseRequestData: []*pbs.CloseConnectionRequestData{
			{ConnectionId: "foo", Reason: session.UnknownReason.String()},
			{ConnectionId: "bar", Reason: session.UnknownReason.String()},
		},
	}
	actual := makeCloseConnectionRequest(in)
	require.ElementsMatch(expected.GetCloseRequestData(), actual.GetCloseRequestData())
}

func TestMakeSessionCloseInfo(t *testing.T) {
	require := require.New(t)
	closeInfo := map[string]string{"foo": "one", "bar": "two"}
	response := &pbs.CloseConnectionResponse{
		CloseResponseData: []*pbs.CloseConnectionResponseData{
			{ConnectionId: "foo", Status: pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED},
			{ConnectionId: "bar", Status: pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED},
		},
	}
	expected := map[string][]*pbs.CloseConnectionResponseData{
		"one": {
			{ConnectionId: "foo", Status: pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED},
		},
		"two": {
			{ConnectionId: "bar", Status: pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED},
		},
	}
	actual, err := makeSessionCloseInfo(closeInfo, response)
	require.NoError(err)
	require.Equal(expected, actual)
}

func TestMakeSessionCloseInfoErrorIfCloseInfoNil(t *testing.T) {
	require := require.New(t)
	actual, err := makeSessionCloseInfo(nil, nil)
	require.Nil(actual)
	require.ErrorIs(err, errMakeSessionCloseInfoNilCloseInfo)
}

func TestMakeSessionCloseInfoEmpty(t *testing.T) {
	require := require.New(t)
	actual, err := makeSessionCloseInfo(make(map[string]string), nil)
	require.NoError(err)
	require.Equal(
		make(map[string][]*pbs.CloseConnectionResponseData),
		actual,
	)
}

func TestMakeFakeSessionCloseInfo(t *testing.T) {
	require := require.New(t)
	closeInfo := map[string]string{"foo": "one", "bar": "two"}
	expected := map[string][]*pbs.CloseConnectionResponseData{
		"one": {
			{ConnectionId: "foo", Status: pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED},
		},
		"two": {
			{ConnectionId: "bar", Status: pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED},
		},
	}
	actual, err := makeFakeSessionCloseInfo(closeInfo)
	require.NoError(err)
	require.Equal(expected, actual)
}

func TestMakeFakeSessionCloseInfoErrorIfCloseInfoNil(t *testing.T) {
	require := require.New(t)
	actual, err := makeFakeSessionCloseInfo(nil)
	require.Nil(actual)
	require.ErrorIs(err, errMakeSessionCloseInfoNilCloseInfo)
}

func TestMakeFakeSessionCloseInfoEmpty(t *testing.T) {
	require := require.New(t)
	actual, err := makeFakeSessionCloseInfo(make(map[string]string))
	require.NoError(err)
	require.Equal(
		make(map[string][]*pbs.CloseConnectionResponseData),
		actual,
	)
}

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
				m.Store("one", &Info{
					Id: "one",
					ConnInfoMap: map[string]*ConnInfo{
						"foo": {Id: "foo"},
					},
				})
				m.Store("two", &Info{
					Id: "two",
					ConnInfoMap: map[string]*ConnInfo{
						"bar": {Id: "bar"},
					},
				})
				m.Store("three", &Info{
					Id: "three",
					ConnInfoMap: map[string]*ConnInfo{
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
				m.Store("one", &Info{
					Id: "one",
					ConnInfoMap: map[string]*ConnInfo{
						"foo": {Id: "foo"},
					},
				})
				m.Store("two", &Info{
					Id: "two",
					ConnInfoMap: map[string]*ConnInfo{
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
				m.Store("one", &Info{
					Id: "one",
					ConnInfoMap: map[string]*ConnInfo{
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
				m.Store("one", &Info{
					Id: "one",
					ConnInfoMap: map[string]*ConnInfo{
						"foo": {Id: "foo"},
					},
				})
				m.Store("two", &Info{Id: "two"})

				return m
			},
			expected: []string{"foo"},
			expectedClosed: map[string]struct{}{
				"foo": {},
			},
			expectedErr: []error{
				errors.New(`could not find connection ID "bar" for session ID "two" in local state after closing connections`),
			},
		},
		{
			name:             "empty",
			sessionCloseInfo: make(map[string][]*pbs.CloseConnectionResponseData),
			sessionInfoMap: func() *sync.Map {
				m := new(sync.Map)
				m.Store("one", &Info{
					Id: "one",
					ConnInfoMap: map[string]*ConnInfo{
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
			sessionInfoMap := tc.sessionInfoMap()
			actual, actualErr := setCloseTimeForResponse(sessionInfoMap, tc.sessionCloseInfo)

			// Assert all close times were set
			sessionInfoMap.Range(func(key, value interface{}) bool {
				t.Helper()
				for _, ci := range value.(*Info).ConnInfoMap {
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
