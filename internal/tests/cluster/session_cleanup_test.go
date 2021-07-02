package cluster

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
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

	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/cmd/config"
	targetspb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/targets"
	"github.com/hashicorp/boundary/internal/proxy"
	"github.com/hashicorp/boundary/internal/servers/controller"
	"github.com/hashicorp/boundary/internal/servers/worker"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/dawdle"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/base62"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wspb"
)

const (
	testSendRecvSendMax                  = 60
	defaultGracePeriod                   = time.Second * 30
	expectConnectionStateOnWorkerTimeout = defaultGracePeriod * 2

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

func TestWorkerSessionCleanup(t *testing.T) {
	require := require.New(t)
	logger := hclog.New(&hclog.LoggerOptions{
		Level: hclog.Trace,
	})

	conf, err := config.DevController()
	require.NoError(err)

	pl, err := net.Listen("tcp", "localhost:0")
	require.NoError(err)
	c1 := controller.NewTestController(t, &controller.TestControllerOpts{
		Config:                 conf,
		InitialResourcesSuffix: "1234567890",
		Logger:                 logger.Named("c1"),
		PublicClusterAddr:      pl.Addr().String(),
	})
	defer c1.Shutdown()

	expectWorkers(t, c1)

	// Wire up the testing proxies
	require.Len(c1.ClusterAddrs(), 1)
	proxy, err := dawdle.NewProxy("tcp", "", c1.ClusterAddrs()[0],
		dawdle.WithListener(pl),
		dawdle.WithRbufSize(512),
		dawdle.WithWbufSize(512),
	)
	require.NoError(err)
	defer proxy.Close()
	require.NotEmpty(t, proxy.ListenerAddr())

	w1 := worker.NewTestWorker(t, &worker.TestWorkerOpts{
		WorkerAuthKms:      c1.Config().WorkerAuthKms,
		InitialControllers: []string{proxy.ListenerAddr()},
		Logger:             logger.Named("w1"),
	})
	defer w1.Shutdown()

	time.Sleep(10 * time.Second)
	expectWorkers(t, c1, w1)

	// Use an independent context for test things that take a context so
	// that we aren't tied to any timeouts in the controller, etc. This
	// can interfere with some of the test operations.
	ctx := context.Background()

	// Connect target
	client := c1.Client()
	client.SetToken(c1.Token().Token)
	tcl := targets.NewClient(client)
	tgt, err := tcl.Read(ctx, "ttcp_1234567890")
	require.NoError(err)
	require.NotNil(tgt)

	// Create test server, update default port on target
	ts := newTestTcpServer(t, logger)
	require.NotNil(t, ts)
	defer ts.Close()
	tgt, err = tcl.Update(ctx, tgt.Item.Id, tgt.Item.Version, targets.WithTcpTargetDefaultPort(ts.Port()))
	require.NoError(err)
	require.NotNil(tgt)

	// Authorize and connect
	sess := newTestSession(ctx, t, logger, tcl, "ttcp_1234567890")
	sConn := sess.Connect(ctx, t, logger)

	// Run initial send/receive test, make sure things are working
	sConn.TestSendRecvAll(t)

	// Kill the link
	proxy.Pause()

	// Run again, ensure connection is dead
	sConn.TestSendRecvFail(t)

	// Assert we have no connections left (should be default behavior)
	sess.TestNoConnectionsLeft(t)

	// Assert connection has been removed from the local worker state
	sess.ExpectConnectionStateOnWorker(ctx, t, w1, session.StatusClosed)

	// Resume the connection, and reconnect.
	proxy.Resume()
	time.Sleep(time.Second * 10)                                  // Sleep to wait for worker to report back as healthy
	sess = newTestSession(ctx, t, logger, tcl, "ttcp_1234567890") // re-assign, other connection will close in t.Cleanup()
	sConn = sess.Connect(ctx, t, logger)
	sConn.TestSendRecvAll(t)
}

func TestWorkerSessionCleanupMultiController(t *testing.T) {
	require := require.New(t)
	logger := hclog.New(&hclog.LoggerOptions{
		Level: hclog.Trace,
	})

	// ******************
	// ** Controller 1 **
	// ******************
	conf1, err := config.DevController()
	require.NoError(err)

	pl1, err := net.Listen("tcp", "localhost:0")
	require.NoError(err)
	c1 := controller.NewTestController(t, &controller.TestControllerOpts{
		Config:                 conf1,
		InitialResourcesSuffix: "1234567890",
		Logger:                 logger.Named("c1"),
		PublicClusterAddr:      pl1.Addr().String(),
	})
	defer c1.Shutdown()

	// ******************
	// ** Controller 2 **
	// ******************
	pl2, err := net.Listen("tcp", "localhost:0")
	require.NoError(err)
	c2 := c1.AddClusterControllerMember(t, &controller.TestControllerOpts{
		Logger:            c1.Config().Logger.ResetNamed("c2"),
		PublicClusterAddr: pl2.Addr().String(),
	})
	defer c2.Shutdown()
	expectWorkers(t, c1)
	expectWorkers(t, c2)

	// *************
	// ** Proxy 1 **
	// *************
	require.Len(c1.ClusterAddrs(), 1)
	p1, err := dawdle.NewProxy("tcp", "", c1.ClusterAddrs()[0],
		dawdle.WithListener(pl1),
		dawdle.WithRbufSize(512),
		dawdle.WithWbufSize(512),
	)
	require.NoError(err)
	defer p1.Close()
	require.NotEmpty(t, p1.ListenerAddr())

	// *************
	// ** Proxy 2 **
	// *************
	require.Len(c2.ClusterAddrs(), 1)
	p2, err := dawdle.NewProxy("tcp", "", c2.ClusterAddrs()[0],
		dawdle.WithListener(pl2),
		dawdle.WithRbufSize(512),
		dawdle.WithWbufSize(512),
	)
	require.NoError(err)
	defer p2.Close()
	require.NotEmpty(t, p2.ListenerAddr())

	// ************
	// ** Worker **
	// ************
	w1 := worker.NewTestWorker(t, &worker.TestWorkerOpts{
		WorkerAuthKms:      c1.Config().WorkerAuthKms,
		InitialControllers: []string{p1.ListenerAddr(), p2.ListenerAddr()},
		Logger:             logger.Named("w1"),
	})
	defer w1.Shutdown()

	time.Sleep(10 * time.Second)
	expectWorkers(t, c1, w1)
	expectWorkers(t, c2, w1)

	// Use an independent context for test things that take a context so
	// that we aren't tied to any timeouts in the controller, etc. This
	// can interfere with some of the test operations.
	ctx := context.Background()

	// Connect target
	client := c1.Client()
	client.SetToken(c1.Token().Token)
	tcl := targets.NewClient(client)
	tgt, err := tcl.Read(ctx, "ttcp_1234567890")
	require.NoError(err)
	require.NotNil(tgt)

	// Create test server, update default port on target
	ts := newTestTcpServer(t, logger)
	require.NotNil(ts)
	defer ts.Close()
	tgt, err = tcl.Update(ctx, tgt.Item.Id, tgt.Item.Version, targets.WithTcpTargetDefaultPort(ts.Port()))
	require.NoError(err)
	require.NotNil(tgt)

	// Authorize and connect
	sess := newTestSession(ctx, t, logger, tcl, "ttcp_1234567890")
	sConn := sess.Connect(ctx, t, logger)

	// Run initial send/receive test, make sure things are working
	sConn.TestSendRecvAll(t)

	// Kill connection to first controller, and run test again, should
	// pass, deferring to other controller.
	p1.Pause()
	sConn.TestSendRecvAll(t)

	// Resume first controller, pause second. This one should work too.
	p1.Resume()
	p2.Pause()
	sConn.TestSendRecvAll(t)

	// Kill the first controller connection again. This one should fail
	// due to lack of any connection.
	p1.Pause()
	sConn.TestSendRecvFail(t)

	// Assert we have no connections left (should be default behavior)
	sess.TestNoConnectionsLeft(t)

	// Assert connection has been removed from the local worker state
	sess.ExpectConnectionStateOnWorker(ctx, t, w1, session.StatusClosed)

	// Finally resume both, try again. Should behave as per normal.
	p1.Resume()
	p2.Resume()
	time.Sleep(time.Second * 10)                                  // Sleep to wait for worker to report back as healthy
	sess = newTestSession(ctx, t, logger, tcl, "ttcp_1234567890") // re-assign, other connection will close in t.Cleanup()
	sConn = sess.Connect(ctx, t, logger)
	sConn.TestSendRecvAll(t)
}

// testSession represents an authorized session.
type testSession struct {
	sessionId       string
	workerAddr      string
	transport       *http.Transport
	tofuToken       string
	connectionsLeft int32
	logger          hclog.Logger
}

// newTestSession authorizes a session and creates all of the data
// necessary to initialize.
func newTestSession(
	ctx context.Context,
	t *testing.T,
	logger hclog.Logger,
	tcl *targets.Client,
	targetId string,
) *testSession {
	t.Helper()
	require := require.New(t)
	sar, err := tcl.AuthorizeSession(ctx, "ttcp_1234567890")
	require.NoError(err)
	require.NotNil(sar)

	s := &testSession{
		sessionId: sar.Item.SessionId,
		logger:    logger,
	}
	authzString := sar.GetItem().(*targets.SessionAuthorization).AuthorizationToken
	marshaled, err := base58.FastBase58Decoding(authzString)
	require.NoError(err)
	require.NotZero(marshaled)

	sessionAuthzData := new(targetspb.SessionAuthorizationData)
	err = proto.Unmarshal(marshaled, sessionAuthzData)
	require.NoError(err)
	require.NotZero(sessionAuthzData.GetWorkerInfo())

	s.workerAddr = sessionAuthzData.GetWorkerInfo()[0].GetAddress()

	parsedCert, err := x509.ParseCertificate(sessionAuthzData.Certificate)
	require.NoError(err)
	require.Len(parsedCert.DNSNames, 1)

	certPool := x509.NewCertPool()
	certPool.AddCert(parsedCert)
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{sessionAuthzData.Certificate},
				PrivateKey:  ed25519.PrivateKey(sessionAuthzData.PrivateKey),
				Leaf:        parsedCert,
			},
		},
		RootCAs:    certPool,
		ServerName: parsedCert.DNSNames[0],
		MinVersion: tls.VersionTLS13,
	}

	s.transport = cleanhttp.DefaultTransport()
	s.transport.DisableKeepAlives = false
	s.transport.TLSClientConfig = tlsConf
	s.transport.IdleConnTimeout = 0

	return s
}

// connect returns a connected websocket for the stored session,
// connecting to the stored workerAddr with the configured transport.
//
// The returned (wrapped) net.Conn should be ready for communication.
func (s *testSession) connect(ctx context.Context, t *testing.T) net.Conn {
	t.Helper()
	require := require.New(t)
	conn, resp, err := websocket.Dial(
		ctx,
		fmt.Sprintf("wss://%s/v1/proxy", s.workerAddr),
		&websocket.DialOptions{
			HTTPClient: &http.Client{
				Transport: s.transport,
			},
			Subprotocols: []string{globals.TcpProxyV1},
		},
	)
	require.NoError(err)
	require.NotNil(conn)
	require.NotNil(resp)
	require.Equal(resp.Header.Get("Sec-WebSocket-Protocol"), globals.TcpProxyV1)

	// Send the handshake.
	if s.tofuToken == "" {
		s.tofuToken, err = base62.Random(20)
	}

	require.NoError(err)
	handshake := proxy.ClientHandshake{TofuToken: s.tofuToken}
	err = wspb.Write(ctx, conn, &handshake)
	require.NoError(err)

	// Receive/check the handshake
	var handshakeResult proxy.HandshakeResult
	err = wspb.Read(ctx, conn, &handshakeResult)
	require.NoError(err)

	// This is just a cursory check to make sure that the handshake is
	// populated. We could check connections remaining too, but that
	// could legitimately be a trivial (zero) value.
	require.NotNil(handshakeResult.GetExpiration())
	s.connectionsLeft = handshakeResult.GetConnectionsLeft()

	return websocket.NetConn(ctx, conn, websocket.MessageBinary)
}

// TestNoConnectionsLeft asserts that there are no connections left.
func (s *testSession) TestNoConnectionsLeft(t *testing.T) {
	t.Helper()
	require.Zero(t, s.connectionsLeft)
}

// ExpectConnectionStateOnWorker waits until all connections in a
// session have transitioned to a particular state on the worker.
func (s *testSession) ExpectConnectionStateOnWorker(
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
	s.logger.Debug("successfully asserted all connection states on worker", "expected_states", expectStates, "actual_states", actualStates)
}

func (s *testSession) testWorkerConnectionInfo(t *testing.T, tw *worker.TestWorker) map[string]worker.TestConnectionInfo {
	t.Helper()
	require := require.New(t)
	si, ok := tw.LookupSession(s.sessionId)
	// This is always an error if the session has been removed from the
	// local state.
	require.True(ok)

	// Likewise, we require the helper to always be used with
	// connections.
	require.Greater(len(si.Connections), 0, "should have at least one connection")

	return si.Connections
}

func (s *testSession) testWorkerConnectionIds(t *testing.T, tw *worker.TestWorker) []string {
	t.Helper()
	conns := s.testWorkerConnectionInfo(t, tw)
	result := make([]string, 0, len(conns))
	for _, conn := range conns {
		result = append(result, conn.Id)
	}

	return result
}

// testSessionConnection abstracts a connected session.
type testSessionConnection struct {
	conn   net.Conn
	logger hclog.Logger
}

// Connect returns a testSessionConnection for a testSession. Check
// the unexported connect method for the lower-level details.
func (s *testSession) Connect(
	ctx context.Context,
	t *testing.T, // Just to add cleanup
	logger hclog.Logger,
) *testSessionConnection {
	t.Helper()
	require := require.New(t)
	conn := s.connect(ctx, t)
	require.NotNil(conn)
	t.Cleanup(func() {
		conn.Close()
	})
	require.NotNil(conn)

	return &testSessionConnection{
		conn:   conn,
		logger: logger,
	}
}

// testSendRecv runs a basic send/receive test over the returned
// connection, and returns whether or not all "pings" made it
// through.
//
// The test is a simple sequence number, ticking up every second to
// max. The passed in conn is expected to copy whatever it is
// received.
func (c *testSessionConnection) testSendRecv(t *testing.T) bool {
	t.Helper()
	require := require.New(t)
	for i := uint32(0); i < testSendRecvSendMax; i++ {
		// Shuttle over the sequence number as base64.
		err := binary.Write(c.conn, binary.LittleEndian, i)
		if err != nil {
			c.logger.Debug("received error during write", "err", err)
			if errors.Is(err, net.ErrClosed) ||
				errors.Is(err, io.EOF) ||
				errors.Is(err, websocket.CloseError{Code: websocket.StatusPolicyViolation, Reason: "timed out"}) {
				return false
			}

			require.FailNow(err.Error())
		}

		// Read it back
		var j uint32
		err = binary.Read(c.conn, binary.LittleEndian, &j)
		if err != nil {
			c.logger.Debug("received error during read", "err", err)
			if errors.Is(err, net.ErrClosed) ||
				errors.Is(err, io.EOF) ||
				errors.Is(err, websocket.CloseError{Code: websocket.StatusPolicyViolation, Reason: "timed out"}) {
				return false
			}

			require.FailNow(err.Error())
		}

		require.Equal(j, i)

		// Sleep 1s
		time.Sleep(time.Second)
	}

	return true
}

// TestSendRecvAll asserts that we were able to send/recv all pings
// over the test connection.
func (c *testSessionConnection) TestSendRecvAll(t *testing.T) {
	t.Helper()
	require.True(t, c.testSendRecv(t))
}

// TestSendRecvFail asserts that we were able to send/recv all pings
// over the test connection.
func (c *testSessionConnection) TestSendRecvFail(t *testing.T) {
	t.Helper()
	require.False(t, c.testSendRecv(t))
}

type testTcpServer struct {
	logger hclog.Logger
	ln     net.Listener
	conns  map[string]net.Conn
}

func (ts *testTcpServer) Port() uint32 {
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

func (ts *testTcpServer) Close() {
	ts.ln.Close()
	for _, conn := range ts.conns {
		conn.Close()
	}
}

func (ts *testTcpServer) run() {
	for {
		conn, err := ts.ln.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				ts.logger.Error("Accept() error in testTcpServer", "err", err)
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

func newTestTcpServer(t *testing.T, logger hclog.Logger) *testTcpServer {
	t.Helper()
	require := require.New(t)
	ts := &testTcpServer{
		logger: logger,
		conns:  make(map[string]net.Conn),
	}
	var err error
	ts.ln, err = net.Listen("tcp", ":0")
	require.NoError(err)

	go ts.run()
	return ts
}
