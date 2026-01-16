// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"
	"fmt"
	"testing"
	"time"

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
			CloseTime:         time.Now(),
		},
	}
	sess := &sess{
		connInfoMap: connInfo,
	}
	assert.ElementsMatch(t, sess.CancelAllLocalConnections(), []string{"1", "2"})
	// We can call the cancel context multiple times, even if it was marked
	// closed previously.
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
		"2": {
			Id:                "2",
			connCtxCancelFunc: cancelFn("2"),
			Status:            pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED,
			CloseTime:         time.Now(),
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
	// We call the cancel context multiple times, even if it was marked
	// closed previously like connection 2 was (by setting CloseTime)
	assert.ElementsMatch(t, closedContextCalled, []string{"1", "2"})
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
