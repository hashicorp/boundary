package worker

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/config"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/shared-secure-libs/configutil"
	"github.com/stretchr/testify/assert"
	grpc "google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type sessionDetail struct {
	status        pbs.SESSIONSTATUS
	connectionIds []string
}

type statusRequestDetail struct {
	sessions map[string]sessionDetail
}

type testController struct {
	statusRequests     []statusRequestDetail
	connCancelRequests []string
	statusErr          error
}

var testStatusErr = errors.New("Status: test failure")

// ServerCoordinationServiceClient impl.
func (c *testController) Status(
	ctx context.Context,
	in *pbs.StatusRequest,
	opts ...grpc.CallOption,
) (*pbs.StatusResponse, error) {
	detail := statusRequestDetail{
		sessions: make(map[string]sessionDetail),
	}

	for _, j := range in.Jobs {
		jobInfo := j.Job.JobInfo.(*pbs.Job_SessionInfo)
		sessionId := jobInfo.SessionInfo.SessionId
		connIds := make([]string, len(jobInfo.SessionInfo.Connections))
		for i, c := range jobInfo.SessionInfo.Connections {
			connIds[i] = c.ConnectionId
		}
		detail.sessions[sessionId] = sessionDetail{
			status:        jobInfo.SessionInfo.Status,
			connectionIds: connIds,
		}
	}

	c.statusRequests = append(c.statusRequests, detail)
	if c.statusErr != nil {
		return nil, c.statusErr
	}

	return new(pbs.StatusResponse), nil
}

// SessionServiceClient impl.
func (c *testController) LookupSession(ctx context.Context,
	in *pbs.LookupSessionRequest,
	opts ...grpc.CallOption,
) (*pbs.LookupSessionResponse, error) {
	return nil, nil
}

// SessionServiceClient impl.
func (c *testController) ActivateSession(
	ctx context.Context,
	in *pbs.ActivateSessionRequest,
	opts ...grpc.CallOption,
) (*pbs.ActivateSessionResponse, error) {
	return nil, nil
}

// SessionServiceClient impl.
func (c *testController) CancelSession(ctx context.Context,
	in *pbs.CancelSessionRequest,
	opts ...grpc.CallOption,
) (*pbs.CancelSessionResponse, error) {
	return nil, nil
}

// SessionServiceClient impl.
func (c *testController) AuthorizeConnection(ctx context.Context,
	in *pbs.AuthorizeConnectionRequest,
	opts ...grpc.CallOption,
) (*pbs.AuthorizeConnectionResponse, error) {
	return nil, nil
}

// SessionServiceClient impl.
func (c *testController) ConnectConnection(ctx context.Context,
	in *pbs.ConnectConnectionRequest,
	opts ...grpc.CallOption,
) (*pbs.ConnectConnectionResponse, error) {
	return nil, nil
}

// SessionServiceClient impl.
func (c *testController) CloseConnection(ctx context.Context,
	in *pbs.CloseConnectionRequest,
	opts ...grpc.CallOption,
) (*pbs.CloseConnectionResponse, error) {
	result := make([]*pbs.CloseConnectionResponseData, len(in.CloseRequestData))
	for i, d := range in.CloseRequestData {
		result[i] = &pbs.CloseConnectionResponseData{
			ConnectionId: d.ConnectionId,
			Status:       pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED,
		}
	}

	return &pbs.CloseConnectionResponse{CloseResponseData: result}, nil
}

func testConnInfoMap(c *testController, id string, status pbs.CONNECTIONSTATUS) map[string]*connInfo {
	return map[string]*connInfo{
		id: &connInfo{
			connCancel: func() { c.connCancelRequests = append(c.connCancelRequests, id) },
			id:         id,
			status:     status,
		},
	}
}

func testSessionInfoMapConnected(m *sync.Map, c *testController) {
	m.Store("foo-sess", &sessionInfo{
		id:     "foo-sess",
		status: pbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE,
		lookupSessionResponse: &pbs.LookupSessionResponse{
			Expiration: timestamppb.New(time.Now().Add(time.Hour)),
		},
		connInfoMap: testConnInfoMap(c, "foo-conn", pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CONNECTED),
	})
	m.Store("bar-sess", &sessionInfo{
		id:     "bar-sess",
		status: pbs.SESSIONSTATUS_SESSIONSTATUS_PENDING,
		lookupSessionResponse: &pbs.LookupSessionResponse{
			Expiration: timestamppb.New(time.Now().Add(time.Hour)),
		},
		connInfoMap: testConnInfoMap(c, "bar-conn", pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_AUTHORIZED),
	})
}

func testSessionInfoMapCanceling(m *sync.Map, c *testController) {
	// Should cancel due to canceling
	m.Store("canceling-sess", &sessionInfo{
		id:     "canceling-sess",
		status: pbs.SESSIONSTATUS_SESSIONSTATUS_CANCELING,
		lookupSessionResponse: &pbs.LookupSessionResponse{
			Expiration: timestamppb.New(time.Now().Add(time.Hour)),
		},
		connInfoMap: testConnInfoMap(c, "canceling-conn", pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CONNECTED),
	})

	// Should cancel due to termination
	m.Store("terminated-sess", &sessionInfo{
		id:     "terminated-sess",
		status: pbs.SESSIONSTATUS_SESSIONSTATUS_TERMINATED,
		lookupSessionResponse: &pbs.LookupSessionResponse{
			Expiration: timestamppb.New(time.Now().Add(time.Hour)),
		},
		connInfoMap: testConnInfoMap(c, "terminated-conn", pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CONNECTED),
	})

	// Should cancel due to expiration
	m.Store("expired-sess", &sessionInfo{
		id:     "expired-sess",
		status: pbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE,
		lookupSessionResponse: &pbs.LookupSessionResponse{
			Expiration: timestamppb.Now(),
		},
		connInfoMap: testConnInfoMap(c, "expired-conn", pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CONNECTED),
	})
}

func testWorker(c *testController) (*Worker, error) {
	w, err := New(&Config{
		Server: &base.Server{
			Logger: hclog.New(&hclog.LoggerOptions{
				Level: hclog.Trace,
			}),
		},
		RawConfig: &config.Config{
			SharedConfig: &configutil.SharedConfig{
				DisableMlock: true,
			},
		},
	})

	if err != nil {
		return nil, err
	}

	w.sessionInfoMap = new(sync.Map)
	w.controllerStatusConn.Store(c)
	w.controllerSessionConn.Store(c)

	return w, nil
}

func TestSendWorkerStatus(t *testing.T) {
	c := new(testController)
	w, err := testWorker(c)
	if err != nil {
		t.Fatal(err)
	}

	assert.NotNil(t, w)

	testSessionInfoMapConnected(w.sessionInfoMap, c)
	testSessionInfoMapCanceling(w.sessionInfoMap, c)

	w.sendWorkerStatus(context.Background())

	// Assert sessions/conns sent status
	assert.Equal(t, c.statusRequests, []statusRequestDetail{
		{
			sessions: map[string]sessionDetail{
				"foo-sess": sessionDetail{
					status:        pbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE,
					connectionIds: []string{"foo-conn"},
				},
				"bar-sess": sessionDetail{
					status:        pbs.SESSIONSTATUS_SESSIONSTATUS_PENDING,
					connectionIds: []string{"bar-conn"},
				},
				"canceling-sess": sessionDetail{
					status:        pbs.SESSIONSTATUS_SESSIONSTATUS_CANCELING,
					connectionIds: []string{"canceling-conn"},
				},
				"terminated-sess": sessionDetail{
					status:        pbs.SESSIONSTATUS_SESSIONSTATUS_TERMINATED,
					connectionIds: []string{"terminated-conn"},
				},
				"expired-sess": sessionDetail{
					status:        pbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE,
					connectionIds: []string{"expired-conn"},
				},
			},
		},
	})

	// Assert cancellation requests
	assert.ElementsMatch(t, c.connCancelRequests, []string{"canceling-conn", "terminated-conn", "expired-conn"})

	// Assert cancellation reaps
	var sessionMapLen int

	// Reaps do not happen immediately after cancellation
	w.sessionInfoMap.Range(func(key, value interface{}) bool {
		sessionMapLen++
		return true
	})
	assert.Equal(t, 5, sessionMapLen)

	// Call again and check reap
	w.sendWorkerStatus(context.Background())
	// Check last call detail
	assert.Equal(t, c.statusRequests[len(c.statusRequests)-1], statusRequestDetail{
		sessions: map[string]sessionDetail{
			"foo-sess": sessionDetail{
				status:        pbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE,
				connectionIds: []string{"foo-conn"},
			},
			"bar-sess": sessionDetail{
				status:        pbs.SESSIONSTATUS_SESSIONSTATUS_PENDING,
				connectionIds: []string{"bar-conn"},
			},
			"canceling-sess": sessionDetail{
				status:        pbs.SESSIONSTATUS_SESSIONSTATUS_CANCELING,
				connectionIds: []string{"canceling-conn"},
			},
			"terminated-sess": sessionDetail{
				status:        pbs.SESSIONSTATUS_SESSIONSTATUS_TERMINATED,
				connectionIds: []string{"terminated-conn"},
			},
			"expired-sess": sessionDetail{
				status:        pbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE,
				connectionIds: []string{"expired-conn"},
			},
		},
	})
	// Session map should now only have 2 entries
	sessionMapLen = 0
	w.sessionInfoMap.Range(func(key, value interface{}) bool {
		sessionMapLen++
		return true
	})
	assert.Equal(t, 2, sessionMapLen)

	// Final call - should be a no-op
	w.sendWorkerStatus(context.Background())
	// Last call detail should just contain connected connections now
	assert.Equal(t, c.statusRequests[len(c.statusRequests)-1], statusRequestDetail{
		sessions: map[string]sessionDetail{
			"foo-sess": sessionDetail{
				status:        pbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE,
				connectionIds: []string{"foo-conn"},
			},
			"bar-sess": sessionDetail{
				status:        pbs.SESSIONSTATUS_SESSIONSTATUS_PENDING,
				connectionIds: []string{"bar-conn"},
			},
		},
	})
	// Session map should (still) only have 2 entries
	sessionMapLen = 0
	w.sessionInfoMap.Range(func(key, value interface{}) bool {
		sessionMapLen++
		return true
	})
	assert.Equal(t, 2, sessionMapLen)
}

func TestSendWorkerStatusError(t *testing.T) {
	c := new(testController)
	w, err := testWorker(c)
	if err != nil {
		t.Fatal(err)
	}

	assert.NotNil(t, w)

	// Just add the connected sessions
	testSessionInfoMapConnected(w.sessionInfoMap, c)

	w.sendWorkerStatus(context.Background())

	// Assert sessions/conns sent status
	assert.Equal(t, c.statusRequests, []statusRequestDetail{
		{
			sessions: map[string]sessionDetail{
				"foo-sess": sessionDetail{
					status:        pbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE,
					connectionIds: []string{"foo-conn"},
				},
				"bar-sess": sessionDetail{
					status:        pbs.SESSIONSTATUS_SESSIONSTATUS_PENDING,
					connectionIds: []string{"bar-conn"},
				},
			},
		},
	})

	// Assert a successful status
	lastStatus := w.LastStatusSuccess()
	assert.NotNil(t, lastStatus)
	// Assert no cancellation requests
	assert.Empty(t, c.connCancelRequests)

	// Add error, sleep, and make request
	c.statusErr = testStatusErr
	time.Sleep(statusFailGrace)
	w.sendWorkerStatus(context.Background())

	// Assert sessions/conns sent status (should be same)
	assert.Equal(t, c.statusRequests[len(c.statusRequests)-1], statusRequestDetail{
		sessions: map[string]sessionDetail{
			"foo-sess": sessionDetail{
				status:        pbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE,
				connectionIds: []string{"foo-conn"},
			},
			"bar-sess": sessionDetail{
				status:        pbs.SESSIONSTATUS_SESSIONSTATUS_PENDING,
				connectionIds: []string{"bar-conn"},
			},
		},
	})

	// Assert last successful status is the same
	assert.Equal(t, w.LastStatusSuccess(), lastStatus)
	// Assert cancellation requests
	assert.ElementsMatch(t, c.connCancelRequests, []string{"foo-conn", "bar-conn"})

	// Assert cancellation reaps
	var sessionMapLen int

	// Reaps do not happen immediately after cancellation
	w.sessionInfoMap.Range(func(key, value interface{}) bool {
		sessionMapLen++
		return true
	})
	assert.Equal(t, 2, sessionMapLen)

	// Call again and check reap
	w.sendWorkerStatus(context.Background())
	// Check last call detail. Session status should never change
	// throughout this process.
	assert.Equal(t, c.statusRequests[len(c.statusRequests)-1], statusRequestDetail{
		sessions: map[string]sessionDetail{
			"foo-sess": sessionDetail{
				status:        pbs.SESSIONSTATUS_SESSIONSTATUS_ACTIVE,
				connectionIds: []string{"foo-conn"},
			},
			"bar-sess": sessionDetail{
				status:        pbs.SESSIONSTATUS_SESSIONSTATUS_PENDING,
				connectionIds: []string{"bar-conn"},
			},
		},
	})
	// Session map should now be empty
	sessionMapLen = 0
	w.sessionInfoMap.Range(func(key, value interface{}) bool {
		sessionMapLen++
		return true
	})
	assert.Zero(t, sessionMapLen)
}
