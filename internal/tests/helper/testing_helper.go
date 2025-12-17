// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package helper

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	apiproxy "github.com/hashicorp/boundary/api/proxy"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/hashicorp/boundary/internal/daemon/worker"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	DefaultControllerRPCGracePeriod          = time.Second * 15
	expectConnectionStateOnControllerTimeout = time.Minute * 2
	expectConnectionStateOnWorkerTimeout     = DefaultControllerRPCGracePeriod * 3

	// This is the interval that we check states on in the worker. It
	// needs to be particularly granular to ensure that we allow for
	// adequate time to catch any edge cases where the connection state
	// disappears from the worker before we can update the state.
	expectConnectionStateOnWorkerInterval = time.Millisecond * 100
)

// TestSession represents an authorized session.
type TestSession struct {
	proxy     *apiproxy.ClientProxy
	SessionId string
}

// NewTestSession authorizes a session and starts a client proxy. Connections
// through the proxy can be established via the `connect` function.
func NewTestSession(
	ctx context.Context,
	t *testing.T,
	tcl *targets.Client,
	targetId string,
	opt ...Option,
) *TestSession {
	t.Helper()

	ctx, cancel := context.WithCancel(ctx)

	require, assert := require.New(t), assert.New(t)

	opts, err := getOpts(opt...)
	require.NoError(err)

	sar, err := tcl.AuthorizeSession(ctx, targetId)
	require.NoError(err)
	require.NotNil(sar)

	sessAuth, err := sar.GetSessionAuthorization()
	require.NoError(err)

	sessAuthData, err := sessAuth.GetSessionAuthorizationData()
	if len(opts.WithWorkerInfo) != 0 {
		sessAuthData.WorkerInfo = opts.WithWorkerInfo
	}
	require.NoError(err)

	proxy, err := apiproxy.New(
		ctx,
		sessAuth.AuthorizationToken,
		apiproxy.WithWorkerHost(sessAuth.SessionId),
		apiproxy.WithSkipSessionTeardown(opts.WithSkipSessionTeardown),
		apiproxy.WithSessionAuthorizationData(sessAuthData),
	)
	require.NoError(err)

	cleanupDone := make(chan struct{}, 1)
	go func() {
		proxyErr := proxy.Start()
		assert.NoError(proxyErr)
		close(cleanupDone)
	}()
	t.Cleanup(func() {
		cancel()
		<-cleanupDone
	})

	return &TestSession{
		proxy:     proxy,
		SessionId: sessAuth.SessionId,
	}
}

// connect returns a connected dialed through the client proxy. The returned
// net.Conn should be ready for communications.
func (s *TestSession) connect(ctx context.Context, t *testing.T) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", s.proxy.ListenerAddress(ctx))
	require.NoError(t, err)
	return conn
}

// ExpectConnectionStateOnController waits until all connections in a
// session have transitioned to a particular state on the controller.
func (s *TestSession) ExpectConnectionStateOnController(
	ctx context.Context,
	t *testing.T,
	connectionRepoFn common.ConnectionRepoFactory,
	expectState session.ConnectionStatus,
) {
	t.Helper()
	require := require.New(t)
	assert := assert.New(t)

	ctx, cancel := context.WithTimeout(ctx, expectConnectionStateOnControllerTimeout)
	defer cancel()

	// This is just for initialization of the actual state set.
	const sessionStatusUnknown session.ConnectionStatus = "unknown"

	connectionRepo, err := connectionRepoFn()
	require.NoError(err)

	conns, err := connectionRepo.ListConnectionsBySessionId(ctx, s.SessionId)
	require.NoError(err)
	// To avoid misleading passing tests, we require this test be used
	// with sessions with connections..
	require.Greater(len(conns), 0, "should have at least one connection")

	// Make a set of states, 1 per connection
	actualStates := make([]session.ConnectionStatus, len(conns))
	for i := range actualStates {
		actualStates[i] = sessionStatusUnknown
	}

	// Make expect set for comparison
	expectStates := make([]session.ConnectionStatus, len(conns))
	for i := range expectStates {
		expectStates[i] = expectState
	}

	for {
		if ctx.Err() != nil {
			break
		}

		for i, conn := range conns {
			c, err := connectionRepo.LookupConnection(ctx, conn.PublicId, nil)
			require.NoError(err)
			actualStates[i] = session.ConnectionStatusFromString(c.Status)
		}

		if reflect.DeepEqual(expectStates, actualStates) {
			break
		}

		time.Sleep(time.Second)
	}

	// "non-fatal" assert here, so that we can surface both timeouts
	// and invalid state
	assert.NoError(ctx.Err())

	// Assert
	require.Equal(expectStates, actualStates)
	t.Log("successfully asserted all connection states on controller", "expected_states", expectStates, "actual_states", actualStates)
}

// ExpectConnectionStateOnWorker waits until all connections in a
// session have transitioned to a particular state on the worker.
func (s *TestSession) ExpectConnectionStateOnWorker(
	ctx context.Context,
	t *testing.T,
	tw *worker.TestWorker,
	expectState session.ConnectionStatus,
) {
	t.Helper()
	require := require.New(t)
	assert := assert.New(t)

	ctx, cancel := context.WithTimeout(ctx, expectConnectionStateOnWorkerTimeout)
	defer cancel()

	// This is just for initialization of the actual state set.
	const sessionStatusUnknown session.ConnectionStatus = "unknown"

	connIds := s.testWorkerConnectionIds(t, tw)
	// Make a set of states, 1 per connection
	actualStates := make(map[string]session.ConnectionStatus, len(connIds))
	for _, id := range connIds {
		actualStates[id] = sessionStatusUnknown
	}

	// Make expect set for comparison
	expectStates := make(map[string]session.ConnectionStatus, len(connIds))
	for _, id := range connIds {
		expectStates[id] = expectState
	}

	for {
		if ctx.Err() != nil {
			break
		}

		for _, conn := range s.testWorkerConnectionInfo(t, tw) {
			actualStates[conn.Id] = session.ConnectionStatusFromProtoVal(conn.Status)
		}

		if reflect.DeepEqual(expectStates, actualStates) {
			break
		}

		time.Sleep(expectConnectionStateOnWorkerInterval)
	}

	// "non-fatal" assert here, so that we can surface both timeouts
	// and invalid state
	assert.NoError(ctx.Err())

	// Assert
	require.Equal(expectStates, actualStates)
	t.Log("successfully asserted all connection states on worker", "expected_states", expectStates, "actual_states", actualStates)
}

func (s *TestSession) testWorkerConnectionInfo(t *testing.T, tw *worker.TestWorker) map[string]worker.TestConnectionInfo {
	t.Helper()
	require := require.New(t)
	si, ok := tw.LookupSession(s.SessionId)
	// This is always an error if the session has been removed from the
	// local state.
	require.True(ok)

	// Likewise, we require the helper to always be used with
	// connections.
	require.Greater(len(si.Connections), 0, "should have at least one connection")

	return si.Connections
}

func (s *TestSession) testWorkerConnectionIds(t *testing.T, tw *worker.TestWorker) []string {
	t.Helper()
	conns := s.testWorkerConnectionInfo(t, tw)
	result := make([]string, 0, len(conns))
	for _, conn := range conns {
		result = append(result, conn.Id)
	}

	return result
}

// TestSessionConnection abstracts a connected session.
type TestSessionConnection struct {
	conn net.Conn
}

// Close a test connection
func (c *TestSessionConnection) Close() error {
	return c.conn.Close()
}

// Connect returns a TestSessionConnection for a TestSession. Check
// the unexported connect method for the lower-level details.
func (s *TestSession) Connect(
	ctx context.Context,
	t *testing.T, // Just to add cleanup
) *TestSessionConnection {
	t.Helper()
	require := require.New(t)
	conn := s.connect(ctx, t)
	require.NotNil(conn)
	t.Cleanup(func() {
		conn.Close()
	})
	require.NotNil(conn)

	return &TestSessionConnection{
		conn: conn,
	}
}

// testSendRecv runs a basic send/receive test over the returned
// connection, and returns whether or not all "pings" made it
// through.
//
// The test is a simple sequence number, ticking up every second to
// max. The passed in conn is expected to copy whatever it is
// received.
func (c *TestSessionConnection) testSendRecv(t *testing.T) bool {
	t.Helper()
	require := require.New(t)

	// This is a fairly arbitrary value, as the send/recv is
	// instantaneous. The main key here is just to make sure that we do
	// it a reasonable amount of times to know the connection is
	// stable.
	const testSendRecvSendMax = 100
	for i := uint32(0); i < testSendRecvSendMax; i++ {
		// Shuttle over the sequence number as base64.
		err := binary.Write(c.conn, binary.LittleEndian, i)
		if err != nil {
			t.Log("received error during write", "err", err)
			if errors.Is(err, net.ErrClosed) ||
				errors.Is(err, io.EOF) ||
				errors.Is(err, websocket.CloseError{Code: websocket.StatusPolicyViolation, Reason: "timed out"}) ||
				errors.Is(err, websocket.CloseError{Code: websocket.StatusNormalClosure, Reason: ""}) {
				return false
			}

			require.FailNow(err.Error())
		}

		// Read it back
		var j uint32
		err = binary.Read(c.conn, binary.LittleEndian, &j)
		if err != nil {
			t.Log("received error during read", "err", err, "num_successfully_sent", i)
			if errors.Is(err, net.ErrClosed) ||
				errors.Is(err, io.EOF) ||
				errors.Is(err, websocket.CloseError{Code: websocket.StatusPolicyViolation, Reason: "timed out"}) {
				return false
			}

			require.FailNow(err.Error())
		}

		require.Equal(j, i)
	}

	t.Log("finished send/recv successfully", "num_successfully_sent", testSendRecvSendMax)
	return true
}

// TestSendRecvAll asserts that we were able to send/recv all pings
// over the test connection.
func (c *TestSessionConnection) TestSendRecvAll(t *testing.T) {
	t.Helper()
	require.True(t, c.testSendRecv(t))
	t.Log("successfully asserted send/recv as passing")
}

// TestSendRecvFail asserts that we were able to send/recv all pings
// over the test connection.
func (c *TestSessionConnection) TestSendRecvFail(t *testing.T) {
	t.Helper()
	require.False(t, c.testSendRecv(t))
	t.Log("successfully asserted send/recv as failing")
}

// TestTcpServer defines a simple testing TCP server. Data is simply
// copied from its input to its output.
type TestTcpServer struct {
	t     *testing.T
	ln    net.Listener
	conns map[string]net.Conn
}

// Port returns the port number for the test server listener.
func (ts *TestTcpServer) Port() uint32 {
	_, portS, err := net.SplitHostPort(ts.ln.Addr().String())
	if err != nil {
		panic(err)
	}

	if portS == "" {
		panic("empty port in what should be TCP listener")
	}

	port, err := strconv.Atoi(portS)
	if err != nil {
		panic(err)
	}

	if port < 1 {
		panic("zero or negative port in what should be a TCP listener")
	}

	return uint32(port)
}

// Close closes the listener and all active connections.
func (ts *TestTcpServer) Close() {
	ts.ln.Close()
	for _, conn := range ts.conns {
		conn.Close()
	}
}

func (ts *TestTcpServer) run() {
	for {
		conn, err := ts.ln.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				ts.t.Error("Accept() error in TestTcpServer", "err", err)
			}

			return
		}

		ts.conns[conn.RemoteAddr().String()] = conn

		go func(c net.Conn) {
			io.Copy(c, c)
			c.Close()
		}(conn)
	}
}

// NewTestTcpServer creates a TestTcpServer and runs it.
func NewTestTcpServer(t *testing.T) *TestTcpServer {
	t.Helper()
	require := require.New(t)
	ts := &TestTcpServer{
		t:     t,
		conns: make(map[string]net.Conn),
	}
	var err error
	ts.ln, err = net.Listen("tcp", ":0")
	require.NoError(err)

	go ts.run()

	require.Eventually(func() bool {
		c, err := net.Dial(ts.ln.Addr().Network(), ts.ln.Addr().String())
		if err != nil {
			return false
		}
		_, err = c.Write([]byte("test"))
		if err != nil {
			return false
		}
		buf := make([]byte, len("test"))
		_, err = c.Read(buf)
		if err != nil {
			return false
		}
		if string(buf) != "test" {
			return false
		}
		if err := c.Close(); err != nil {
			return false
		}
		return true
	}, 10*time.Second, 100*time.Millisecond)

	return ts
}

// ExpectWorkers is a blocking call, where the method validates that the expected workers
// can be found in the controllers status update. If the provided list of workers is empty,
// this method will validate that the controller worker routing info is not called.
func ExpectWorkers(t *testing.T, c *controller.TestController, workers ...*worker.TestWorker) {
	t.Helper()
	// validate the controller has no reported workers
	if len(workers) == 0 {
		assert.Eventually(t, func() bool {
			workers := []string{}
			c.Controller().WorkerRoutingInfoUpdateTimes().Range(func(workerId, lastRoutingInfo any) bool {
				if assert.NotNil(t, workerId) {
					return false
				}
				if assert.NotNil(t, lastRoutingInfo) {
					return false
				}
				if time.Since(lastRoutingInfo.(time.Time)) < DefaultControllerRPCGracePeriod {
					workers = append(workers, workerId.(string))
				}
				return true
			})
			return len(workers) == 0
		}, 2*DefaultControllerRPCGracePeriod, 250*time.Millisecond)
		return
	}

	// validate the controller has expected workers
	wg := new(sync.WaitGroup)
	for _, w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assert.NoError(t, w.Worker().WaitForNextSuccessfulRoutingInfoUpdate())
			assert.Eventually(t, func() bool {
				_, ok := c.Controller().WorkerRoutingInfoUpdateTimes().Load(w.Name())
				return ok
			}, 30*time.Second, time.Second)
		}()
	}
	wg.Wait()
}
