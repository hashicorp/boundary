// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package helper

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/cmd/commands/connect"
	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/hashicorp/boundary/internal/daemon/worker"
	"github.com/hashicorp/boundary/internal/proxy"
	"github.com/hashicorp/boundary/internal/session"
	targetspb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/targets"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wspb"
)

const (
	DefaultWorkerStatusGracePeriod           = time.Second * 15
	DefaultSuccessfulStatusGracePeriod       = time.Second * 15
	expectConnectionStateOnControllerTimeout = time.Minute * 2
	expectConnectionStateOnWorkerTimeout     = DefaultWorkerStatusGracePeriod * 3

	// This is the interval that we check states on in the worker. It
	// needs to be particularly granular to ensure that we allow for
	// adequate time to catch any edge cases where the connection state
	// disappears from the worker before we can update the state.
	//
	// As of this writing, the (hardcoded) status request interval on
	// the worker is 2 seconds, and a session is removed from the state
	// when it has no connections left on the *next* pass. A one second
	// interval would only mean two chances to check with a high
	// possibility of skew; while it seems okay I'm still not 100%
	// comfortable with this little resolution.
	expectConnectionStateOnWorkerInterval = time.Millisecond * 100
)

// TestSession represents an authorized session.
type TestSession struct {
	SessionId        string
	WorkerAddr       string
	Transport        *http.Transport
	tofuToken        string
	connectionsLeft  int32
	SessionAuthzData *targetspb.SessionAuthorizationData
}

// NewTestSession authorizes a session and creates all of the data
// necessary to initialize.
func NewTestSession(
	ctx context.Context,
	t *testing.T,
	tcl *targets.Client,
	targetId string,
) *TestSession {
	t.Helper()
	require := require.New(t)
	sar, err := tcl.AuthorizeSession(ctx, targetId)
	require.NoError(err)
	require.NotNil(sar)

	s := &TestSession{
		SessionId: sar.Item.SessionId,
	}
	authzString := sar.GetItem().(*targets.SessionAuthorization).AuthorizationToken
	marshaled, err := base58.FastBase58Decoding(authzString)
	require.NoError(err)
	require.NotZero(marshaled)

	s.SessionAuthzData = new(targetspb.SessionAuthorizationData)
	err = proto.Unmarshal(marshaled, s.SessionAuthzData)
	require.NoError(err)
	require.NotZero(s.SessionAuthzData.GetWorkerInfo())

	s.WorkerAddr = s.SessionAuthzData.GetWorkerInfo()[0].GetAddress()

	tlsConf, err := connect.ClientTlsConfig(s.SessionAuthzData, "")
	require.NoError(err)

	s.Transport = cleanhttp.DefaultTransport()
	s.Transport.DisableKeepAlives = false
	s.Transport.TLSClientConfig = tlsConf
	s.Transport.IdleConnTimeout = 0

	return s
}

// connect returns a connected websocket for the stored session,
// connecting to the stored workerAddr with the configured transport.
//
// The returned (wrapped) net.Conn should be ready for communication.
func (s *TestSession) connect(ctx context.Context, t *testing.T) net.Conn {
	t.Helper()
	require := require.New(t)

	var conn *websocket.Conn
	var resp *http.Response
	var handshakeResult proxy.HandshakeResult
	// A retry was added here to mitigate some flakiness.
	// Occasionally, `wspb.Read` would throw an error due to "received header with unexpected
	// rsv bits set: false:false:true". It was unclear what the cause of this was, so we
	// resorted to retrying the connection.
	err := backoff.RetryNotify(
		func() error {
			var err error
			conn, resp, err = websocket.Dial(
				ctx,
				fmt.Sprintf("wss://%s/v1/proxy", s.WorkerAddr),
				&websocket.DialOptions{
					HTTPClient: &http.Client{
						Transport: s.Transport,
					},
					Subprotocols: []string{globals.TcpProxyV1},
				},
			)
			if err != nil {
				return backoff.Permanent(err)
			}
			if resp.Header.Get("Sec-WebSocket-Protocol") != globals.TcpProxyV1 {
				return backoff.Permanent(errors.New(
					fmt.Sprintf("Unexpected header. Expected: %s, Actual: %s",
						globals.TcpProxyV1,
						resp.Header.Get("Sec-WebSocket-Protocol"),
					)))
			}

			// Send and receive/check the handshake.
			if s.tofuToken == "" {
				s.tofuToken, err = base62.Random(20)
				if err != nil {
					return backoff.Permanent(errors.New("Error creating token"))
				}
			}
			handshake := proxy.ClientHandshake{TofuToken: s.tofuToken}
			t.Logf("Using token: %s", s.tofuToken)

			err = wspb.Write(ctx, conn, &handshake)
			if err != nil {
				return backoff.Permanent(err)
			}

			return wspb.Read(ctx, conn, &handshakeResult)
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 1),
		func(err error, td time.Duration) {
			t.Logf("Issue with reading websocket: %s. Retrying...", err)
		},
	)
	require.NoError(err)

	// This is just a cursory check to make sure that the handshake is
	// populated. We could check connections remaining too, but that
	// could legitimately be a trivial (zero) value.
	require.NotNil(handshakeResult.GetExpiration())
	s.connectionsLeft = handshakeResult.GetConnectionsLeft()

	return websocket.NetConn(ctx, conn, websocket.MessageBinary)
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
			_, states, err := connectionRepo.LookupConnection(ctx, conn.PublicId, nil)
			require.NoError(err)
			// Look at the first state in the returned list, which will
			// be the most recent state.
			actualStates[i] = states[0].Status
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
func (t *TestSessionConnection) Close() error {
	return t.conn.Close()
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

		// Sleep 1s
		// time.Sleep(time.Second)
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
	return ts
}
