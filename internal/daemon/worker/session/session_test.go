// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"
	"fmt"
	"testing"

	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSession_ApplyLocalStatus(t *testing.T) {
	sess := &sess{
		status: pbs.SESSIONSTATUS_SESSIONSTATUS_PENDING,
	}
	for _, s := range []pbs.SESSIONSTATUS{
		pbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE,
		pbs.SESSIONSTATUS_SESSIONSTATUS_PENDING,
		pbs.SESSIONSTATUS_SESSIONSTATUS_CANCELING,
		pbs.SESSIONSTATUS_SESSIONSTATUS_TERMINATED,
	} {
		sess.ApplyLocalStatus(s)
		assert.Equal(t, s, sess.GetStatus())
	}
}

func TestSession_CancelAllLocalConnections(t *testing.T) {
	var closedContextCalled []string
	cancelFn := func(id string) context.CancelFunc {
		return func() {
			closedContextCalled = append(closedContextCalled, id)
		}
	}
	connInfo := map[string]*ConnInfo{
		"1": {
			Id:                "1",
			connCtxCancelFunc: cancelFn("1"),
		},
		"2": {
			Id:                "2",
			connCtxCancelFunc: cancelFn("2"),
		},
		"3": {
			Id:                "3",
			connCtxCancelFunc: cancelFn("3"),
		},
	}
	sess := &sess{
		connInfoMap: connInfo,
	}
	assert.ElementsMatch(t, sess.CancelAllLocalConnections(), []string{"1", "2", "3"})
	assert.ElementsMatch(t, closedContextCalled, []string{"1", "2", "3"})
}

func TestSession_CancelOpenLocalConnections(t *testing.T) {
	var closedContextCalled []string
	cancelFn := func(id string) context.CancelFunc {
		return func() {
			closedContextCalled = append(closedContextCalled, id)
		}
	}
	connInfo := map[string]*ConnInfo{
		"1": {
			Id:                "1",
			connCtxCancelFunc: cancelFn("1"),
			Status:            pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED,
		},
		"3": {
			Id:                "3",
			connCtxCancelFunc: cancelFn("3"),
			Status:            pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CONNECTED,
		},
	}
	sess := &sess{
		connInfoMap: connInfo,
	}
	assert.ElementsMatch(t, sess.CancelOpenLocalConnections(), []string{"1"})
	assert.ElementsMatch(t, closedContextCalled, []string{"1"})
}

func TestSession_RequestActivate(t *testing.T) {
	mockClient := pbs.NewMockSessionServiceClient()
	mockClient.ActivateSessionFn = func(context.Context, *pbs.ActivateSessionRequest) (*pbs.ActivateSessionResponse, error) {
		return nil, fmt.Errorf("test error")
	}
	sess := &sess{
		client: mockClient,
		resp: &pbs.LookupSessionResponse{
			TofuToken:       "tofu",
			Version:         1,
			Status:          pbs.SESSIONSTATUS_SESSIONSTATUS_PENDING,
			ConnectionLimit: -1,
		},
		status: pbs.SESSIONSTATUS_SESSIONSTATUS_PENDING,
	}
	assert.Error(t, sess.RequestActivate(context.Background(), "tofu"))

	mockClient.ActivateSessionFn = func(context.Context, *pbs.ActivateSessionRequest) (*pbs.ActivateSessionResponse, error) {
		return &pbs.ActivateSessionResponse{Status: pbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE}, nil
	}
	assert.NoError(t, sess.RequestActivate(context.Background(), "tofu"))
	assert.Equal(t, pbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE, sess.GetStatus())
}

func TestSession_RequestCancel(t *testing.T) {
	mockClient := pbs.NewMockSessionServiceClient()
	mockClient.CancelSessionFn = func(context.Context, *pbs.CancelSessionRequest) (*pbs.CancelSessionResponse, error) {
		return nil, fmt.Errorf("test error")
	}
	sess := &sess{
		client: mockClient,
		resp: &pbs.LookupSessionResponse{
			TofuToken:       "tofu",
			Version:         1,
			Status:          pbs.SESSIONSTATUS_SESSIONSTATUS_PENDING,
			ConnectionLimit: -1,
		},
		status: pbs.SESSIONSTATUS_SESSIONSTATUS_PENDING,
	}
	assert.Error(t, sess.RequestCancel(context.Background()))

	mockClient.CancelSessionFn = func(context.Context, *pbs.CancelSessionRequest) (*pbs.CancelSessionResponse, error) {
		return &pbs.CancelSessionResponse{Status: pbs.SESSIONSTATUS_SESSIONSTATUS_CANCELING}, nil
	}
	assert.NoError(t, sess.RequestCancel(context.Background()))
	assert.Equal(t, pbs.SESSIONSTATUS_SESSIONSTATUS_CANCELING, sess.GetStatus())
}

func TestSession_RequestAuthorizeConnection(t *testing.T) {
	mockClient := pbs.NewMockSessionServiceClient()
	mockClient.AuthorizeConnectionFn = func(ctx context.Context, request *pbs.AuthorizeConnectionRequest) (*pbs.AuthorizeConnectionResponse, error) {
		return nil, fmt.Errorf("test error")
	}
	sess := &sess{
		client:      mockClient,
		connInfoMap: make(map[string]*ConnInfo),
		resp: &pbs.LookupSessionResponse{
			TofuToken:       "tofu",
			Version:         1,
			Status:          pbs.SESSIONSTATUS_SESSIONSTATUS_PENDING,
			ConnectionLimit: -1,
		},
		status: pbs.SESSIONSTATUS_SESSIONSTATUS_PENDING,
	}
	_, cancel := context.WithCancel(context.Background())
	resp, _, err := sess.RequestAuthorizeConnection(context.Background(), "workerid", cancel)
	require.Error(t, err)
	assert.Nil(t, resp)

	mockClient.AuthorizeConnectionFn = func(ctx context.Context, request *pbs.AuthorizeConnectionRequest) (*pbs.AuthorizeConnectionResponse, error) {
		return &pbs.AuthorizeConnectionResponse{
			ConnectionId:    "conn1",
			Status:          pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_AUTHORIZED,
			ConnectionsLeft: -1,
		}, nil
	}
	resp, left, err := sess.RequestAuthorizeConnection(context.Background(), "workerid", cancel)
	require.NoError(t, err)
	require.NotNil(t, resp)

	conn := sess.GetLocalConnections()[resp.GetConnectionId()]

	assert.Equal(t, "conn1", conn.Id)
	assert.Equal(t, pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_AUTHORIZED, conn.Status)
	assert.NotNil(t, conn.BytesUp)
	assert.NotNil(t, conn.BytesDown)
	assert.Zero(t, conn.BytesUp())
	assert.Zero(t, conn.BytesDown())
	assert.Equal(t, int32(-1), left)
}

func TestWorkerMakeCloseConnectionRequest(t *testing.T) {
	require := require.New(t)
	in := map[string]*ConnectionCloseData{
		"foo": {SessionId: "one", BytesUp: 1000, BytesDown: 2000},
		"bar": {SessionId: "two", BytesUp: 1000, BytesDown: 2000},
	}
	expected := &pbs.CloseConnectionRequest{
		CloseRequestData: []*pbs.CloseConnectionRequestData{
			{ConnectionId: "foo", Reason: session.UnknownReason.String(), BytesUp: 1000, BytesDown: 2000},
			{ConnectionId: "bar", Reason: session.UnknownReason.String(), BytesUp: 1000, BytesDown: 2000},
		},
	}
	actual := makeCloseConnectionRequest(in)
	require.ElementsMatch(expected.GetCloseRequestData(), actual.GetCloseRequestData())
}

func TestMakeSessionCloseInfo(t *testing.T) {
	require := require.New(t)
	closeInfo := map[string]*ConnectionCloseData{"foo": {SessionId: "one"}, "bar": {SessionId: "two"}}
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
	actual, err := makeSessionCloseInfo(make(map[string]*ConnectionCloseData), nil)
	require.NoError(err)
	require.Equal(
		make(map[string][]*pbs.CloseConnectionResponseData),
		actual,
	)
}

func TestMakeFakeSessionCloseInfo(t *testing.T) {
	require := require.New(t)
	closeInfo := map[string]*ConnectionCloseData{"foo": {SessionId: "one"}, "bar": {SessionId: "two"}}
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
	actual, err := makeFakeSessionCloseInfo(make(map[string]*ConnectionCloseData))
	require.NoError(err)
	require.Equal(
		make(map[string][]*pbs.CloseConnectionResponseData),
		actual,
	)
}

// TestSession_ApplyLocalConnectionStatus_Closed verifies that marking a
// connection closed cancels its proxy context and removes it from the map.
func TestSession_ApplyLocalConnectionStatus_Closed(t *testing.T) {
	cancelled := false
	s := &sess{
		sessionId: "sess1",
		connInfoMap: map[string]*ConnInfo{
			"conn1": {
				Id:     "conn1",
				Status: pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_AUTHORIZED,
				connCtxCancelFunc: func() {
					cancelled = true
				},
			},
		},
	}

	require.NoError(t, s.ApplyLocalConnectionStatus("conn1", pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED))
	assert.True(t, cancelled, "cancel func should have been called")
	_, exists := s.connInfoMap["conn1"]
	assert.False(t, exists, "closed connection should be removed from connInfoMap")
}

// TestSession_ApplyLocalConnectionStatus_NilCancelFunc verifies that a nil
// cancel func is handled safely and the entry is still deleted.
func TestSession_ApplyLocalConnectionStatus_NilCancelFunc(t *testing.T) {
	s := &sess{
		sessionId: "sess1",
		connInfoMap: map[string]*ConnInfo{
			"conn1": {
				Id:                "conn1",
				Status:            pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_AUTHORIZED,
				connCtxCancelFunc: nil,
			},
		},
	}

	require.NoError(t, s.ApplyLocalConnectionStatus("conn1", pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED))
	_, exists := s.connInfoMap["conn1"]
	assert.False(t, exists, "closed connection should be removed even when cancel func is nil")
}

// TestSession_ApplyLocalConnectionStatus_NonClosed verifies that a non-closed
// status update leaves the entry in the map.
func TestSession_ApplyLocalConnectionStatus_NonClosed(t *testing.T) {
	s := &sess{
		sessionId: "sess1",
		connInfoMap: map[string]*ConnInfo{
			"conn1": {
				Id:     "conn1",
				Status: pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_AUTHORIZED,
			},
		},
	}

	require.NoError(t, s.ApplyLocalConnectionStatus("conn1", pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CONNECTED))
	conn, exists := s.connInfoMap["conn1"]
	require.True(t, exists, "non-closed connection should remain in connInfoMap")
	assert.Equal(t, pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CONNECTED, conn.Status)
}

// TestSession_ApplyLocalConnectionStatus_UnknownConnection verifies that an
// error is returned for an unknown connection ID.
func TestSession_ApplyLocalConnectionStatus_UnknownConnection(t *testing.T) {
	s := &sess{
		sessionId:   "sess1",
		connInfoMap: make(map[string]*ConnInfo),
	}
	err := s.ApplyLocalConnectionStatus("nonexistent", pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent")
	assert.Contains(t, err.Error(), "sess1")
}

// TestSession_CancelAllLocalConnections_Empty verifies that an empty map
// returns an empty slice.
func TestSession_CancelAllLocalConnections_Empty(t *testing.T) {
	s := &sess{connInfoMap: make(map[string]*ConnInfo)}
	assert.Empty(t, s.CancelAllLocalConnections())
}

// TestSession_CancelOpenLocalConnections_Empty verifies that an empty map
// returns an empty slice.
func TestSession_CancelOpenLocalConnections_Empty(t *testing.T) {
	s := &sess{connInfoMap: make(map[string]*ConnInfo)}
	assert.Empty(t, s.CancelOpenLocalConnections())
}

// TestSession_CancelOpenLocalConnections_MixedStatuses verifies that only
// CLOSED connections are cancelled across all possible connection statuses.
func TestSession_CancelOpenLocalConnections_MixedStatuses(t *testing.T) {
	var cancelled []string
	cancelFn := func(id string) context.CancelFunc {
		return func() { cancelled = append(cancelled, id) }
	}
	s := &sess{
		connInfoMap: map[string]*ConnInfo{
			"authorized": {
				Id:                "authorized",
				connCtxCancelFunc: cancelFn("authorized"),
				Status:            pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_AUTHORIZED,
			},
			"connected": {
				Id:                "connected",
				connCtxCancelFunc: cancelFn("connected"),
				Status:            pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CONNECTED,
			},
			"closed": {
				Id:                "closed",
				connCtxCancelFunc: cancelFn("closed"),
				Status:            pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED,
			},
		},
	}

	result := s.CancelOpenLocalConnections()
	assert.ElementsMatch(t, []string{"closed"}, result)
	assert.ElementsMatch(t, []string{"closed"}, cancelled)
}

func TestApplyConnectionCounterCallbacks(t *testing.T) {
	s := &sess{connInfoMap: make(map[string]*ConnInfo)}

	connId := "conn1"
	bytesUpFn := func() int64 { return 10 }
	bytesDnFn := func() int64 { return 20 }
	err := s.ApplyConnectionCounterCallbacks(connId, bytesUpFn, bytesDnFn)
	require.EqualError(t, err, "failed to find connection info for connection id \"conn1\"")

	s.connInfoMap[connId] = &ConnInfo{}
	require.NoError(t, s.ApplyConnectionCounterCallbacks("conn1", bytesUpFn, bytesDnFn))

	ci, ok := s.connInfoMap[connId]
	require.True(t, ok)
	require.NotNil(t, ci.BytesUp)
	require.NotNil(t, ci.BytesDown)
	require.EqualValues(t, ci.BytesUp(), 10)
	require.EqualValues(t, ci.BytesDown(), 20)
}
