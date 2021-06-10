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
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/base62"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/require"
	"github.com/vancluever/dwadle"
	"google.golang.org/protobuf/proto"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wspb"
)

func TestWorkerSessionCleanup(t *testing.T) {
	logger := hclog.New(&hclog.LoggerOptions{
		Level: hclog.Trace,
	})

	conf, err := config.DevController()
	require.NoError(t, err)

	pl, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	c1 := controller.NewTestController(t, &controller.TestControllerOpts{
		Config:                 conf,
		InitialResourcesSuffix: "1234567890",
		Logger:                 logger.Named("c1"),
		PublicClusterAddr:      pl.Addr().String(),
	})
	defer c1.Shutdown()

	expectWorkers(t, c1)

	ctx := c1.Context()

	// Wire up the testing proxies
	require.Len(t, c1.ClusterAddrs(), 1)
	proxy, err := dwadle.NewProxy("tcp", "", c1.ClusterAddrs()[0],
		dwadle.WithListener(pl),
		dwadle.WithRbufSize(512),
		dwadle.WithWbufSize(512),
	)
	require.NoError(t, err)
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

	// Connect target
	client := c1.Client()
	client.SetToken(c1.Token().Token)
	tcl := targets.NewClient(client)
	tgt, err := tcl.Read(ctx, "ttcp_1234567890")
	require.NoError(t, err)
	require.NotNil(t, tgt)

	// Create test server, update default port on target
	ts := newTestTcpServer(t)
	require.NotNil(t, ts)
	defer ts.Close()
	tgt, err = tcl.Update(ctx, tgt.Item.Id, tgt.Item.Version, targets.WithTcpTargetDefaultPort(ts.Port()))
	require.NoError(t, err)
	require.NotNil(t, tgt)

	// Authorize
	sar, err := tcl.AuthorizeSession(ctx, "ttcp_1234567890")
	require.NoError(t, err)
	require.NotNil(t, sar)

	tsad := newTestSessionAuthData(t, sar)
	require.NotNil(t, tsad)

	// Connect to worker proxy
	conn := tsad.Connect(ctx, false)
	require.NotNil(t, conn)
	defer conn.Close()

	// Run initial send/receive test, make sure things are working
	actualSendRecv := testSendRecv(t, conn, 60)
	require.Equal(t, actualSendRecv, 60)

	// Kill the link
	proxy.Pause()

	// Run again, ensure connection is dead. Just check to make sure we
	// didn't receive the full set of pings, as the actual figure will
	// likely vary.
	actualSendRecv = testSendRecv(t, conn, 60)
	require.Less(t, actualSendRecv, 60)

	// Resume the connection, and reconnect.
	proxy.Resume()
	conn.Close()                   // Close the last connection
	conn = tsad.Connect(ctx, true) // Assert our token is no longer good
	require.Nil(t, conn)
	time.Sleep(time.Second * 10)                            // Sleep to wait for worker to report back as healthy
	sar, err = tcl.AuthorizeSession(ctx, "ttcp_1234567890") // Re-authorize
	require.NoError(t, err)
	require.NotNil(t, sar)
	tsad = newTestSessionAuthData(t, sar)
	require.NotNil(t, tsad)
	conn = tsad.Connect(ctx, false) // Should be good now
	require.NotNil(t, conn)
	defer conn.Close()
	actualSendRecv = testSendRecv(t, conn, 60)
	require.Equal(t, actualSendRecv, 60)
}

func TestWorkerSessionCleanupMultiController(t *testing.T) {
	logger := hclog.New(&hclog.LoggerOptions{
		Level: hclog.Trace,
	})

	// ******************
	// ** Controller 1 **
	// ******************
	conf1, err := config.DevController()
	require.NoError(t, err)

	pl1, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	c1 := controller.NewTestController(t, &controller.TestControllerOpts{
		Config:                 conf1,
		InitialResourcesSuffix: "1234567890",
		Logger:                 logger.Named("c1"),
		PublicClusterAddr:      pl1.Addr().String(),
	})
	defer c1.Shutdown()
	ctx := c1.Context()

	// ******************
	// ** Controller 2 **
	// ******************
	pl2, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
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
	require.Len(t, c1.ClusterAddrs(), 1)
	p1, err := dwadle.NewProxy("tcp", "", c1.ClusterAddrs()[0],
		dwadle.WithListener(pl1),
		dwadle.WithRbufSize(512),
		dwadle.WithWbufSize(512),
	)
	require.NoError(t, err)
	defer p1.Close()
	require.NotEmpty(t, p1.ListenerAddr())

	// *************
	// ** Proxy 2 **
	// *************
	require.Len(t, c2.ClusterAddrs(), 1)
	p2, err := dwadle.NewProxy("tcp", "", c2.ClusterAddrs()[0],
		dwadle.WithListener(pl2),
		dwadle.WithRbufSize(512),
		dwadle.WithWbufSize(512),
	)
	require.NoError(t, err)
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

	// Connect target
	client := c1.Client()
	client.SetToken(c1.Token().Token)
	tcl := targets.NewClient(client)
	tgt, err := tcl.Read(ctx, "ttcp_1234567890")
	require.NoError(t, err)
	require.NotNil(t, tgt)

	// Create test server, update default port on target
	ts := newTestTcpServer(t)
	require.NotNil(t, ts)
	defer ts.Close()
	tgt, err = tcl.Update(ctx, tgt.Item.Id, tgt.Item.Version, targets.WithTcpTargetDefaultPort(ts.Port()))
	require.NoError(t, err)
	require.NotNil(t, tgt)

	// Authorize
	sar, err := tcl.AuthorizeSession(ctx, "ttcp_1234567890")
	require.NoError(t, err)
	require.NotNil(t, sar)

	tsad := newTestSessionAuthData(t, sar)
	require.NotNil(t, tsad)

	// Connect to worker proxy
	conn := tsad.Connect(ctx, false)
	require.NotNil(t, conn)
	defer conn.Close()

	// Run initial send/receive test, make sure things are working
	actualSendRecv := testSendRecv(t, conn, 60)
	require.Equal(t, actualSendRecv, 60)

	// Kill connection to first controller, and run test again, should
	// pass, deferring to other controller.
	p1.Pause()
	actualSendRecv = testSendRecv(t, conn, 60)
	require.Equal(t, actualSendRecv, 60)

	// Resume first controller, pause second. This one should work too.
	p1.Resume()
	p2.Pause()
	actualSendRecv = testSendRecv(t, conn, 60)
	require.Equal(t, actualSendRecv, 60)

	// Kill the first controller connection again. This one should fail
	// due to lack of any connection.
	p1.Pause()
	actualSendRecv = testSendRecv(t, conn, 60)
	require.Less(t, actualSendRecv, 60)

	// Finally resume both, try again. Should behave as per normal.
	// Resume first controller, pause second. This one should work too.
	p1.Resume()
	p2.Resume()
	conn.Close()                   // Close the last connection
	conn = tsad.Connect(ctx, true) // Assert our token is no longer good
	require.Nil(t, conn)
	time.Sleep(time.Second * 10)                            // Sleep to wait for worker to report back as healthy
	sar, err = tcl.AuthorizeSession(ctx, "ttcp_1234567890") // Re-authorize
	require.NoError(t, err)
	require.NotNil(t, sar)
	tsad = newTestSessionAuthData(t, sar)
	require.NotNil(t, tsad)
	conn = tsad.Connect(ctx, false) // Should be good now
	require.NotNil(t, conn)
	defer conn.Close()
	actualSendRecv = testSendRecv(t, conn, 60)
	require.Equal(t, actualSendRecv, 60)
}

// testSendRecv runs a basic send/receive test over the returned
// connection and returns the amount of "pings" successfully sent.
//
// The test is a simple sequence number, ticking up every second to
// max. The passed in conn is expected to copy whatever it is
// received.
func testSendRecv(t *testing.T, conn net.Conn, max uint32) int {
	t.Helper()

	var i uint32
	for ; i < max; i++ {
		// Shuttle over the sequence number as base64.
		err := binary.Write(conn, binary.LittleEndian, i)
		if err != nil {
			if errors.Is(err, net.ErrClosed) ||
				errors.Is(err, io.EOF) ||
				errors.Is(err, &websocket.CloseError{Code: websocket.StatusPolicyViolation, Reason: "timed out"}) {
				break
			}

			require.FailNow(t, err.Error())
		}

		// Read it back
		var j uint32
		err = binary.Read(conn, binary.LittleEndian, &j)
		if err != nil {
			if errors.Is(err, net.ErrClosed) ||
				errors.Is(err, io.EOF) ||
				errors.Is(err, &websocket.CloseError{Code: websocket.StatusPolicyViolation, Reason: "timed out"}) {
				break
			}

			require.FailNow(t, err.Error())
		}

		require.Equal(t, j, i)

		// Sleep 1s
		time.Sleep(time.Second)
	}

	return int(i)
}

type testSessionAuthData struct {
	t          *testing.T
	workerAddr string
	transport  *http.Transport
}

// newTestSessionAuthData derives a bunch of authorization data that
// we need from a session's authorization token. This is a relatively
// complex process that does not have much to do with describing the
// test, and may need to be repeated, so we abstract it here.
func newTestSessionAuthData(t *testing.T, sar *targets.SessionAuthorizationResult) *testSessionAuthData {
	t.Helper()
	result := &testSessionAuthData{
		t: t,
	}

	authzString := sar.GetItem().(*targets.SessionAuthorization).AuthorizationToken
	marshaled, err := base58.FastBase58Decoding(authzString)
	require.NoError(t, err)
	require.NotZero(t, marshaled)

	sessionAuthzData := new(targetspb.SessionAuthorizationData)
	err = proto.Unmarshal(marshaled, sessionAuthzData)
	require.NoError(t, err)
	require.NotZero(t, sessionAuthzData.GetWorkerInfo())

	result.workerAddr = sessionAuthzData.GetWorkerInfo()[0].GetAddress()

	parsedCert, err := x509.ParseCertificate(sessionAuthzData.Certificate)
	require.NoError(t, err)
	require.Len(t, parsedCert.DNSNames, 1)

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

	result.transport = cleanhttp.DefaultTransport()
	result.transport.DisableKeepAlives = false
	result.transport.TLSClientConfig = tlsConf
	result.transport.IdleConnTimeout = 0

	return result
}

// Connect returns a connected websocket for the stored session auth
// data, connecting to the stored workerAddr with the configured
// transport.
//
// The returned (wrapped) net.Conn should be ready for communication.
func (d *testSessionAuthData) Connect(ctx context.Context, expectExpired bool) net.Conn {
	d.t.Helper()

	conn, resp, err := websocket.Dial(
		ctx,
		fmt.Sprintf("wss://%s/v1/proxy", d.workerAddr),
		&websocket.DialOptions{
			HTTPClient: &http.Client{
				Transport: d.transport,
			},
			Subprotocols: []string{globals.TcpProxyV1},
		},
	)
	require.NoError(d.t, err)
	require.NotNil(d.t, conn)
	require.NotNil(d.t, resp)
	require.Equal(d.t, resp.Header.Get("Sec-WebSocket-Protocol"), globals.TcpProxyV1)

	// Send the handshake.
	tofuToken, err := base62.Random(20)
	require.NoError(d.t, err)
	handshake := proxy.ClientHandshake{TofuToken: tofuToken}
	err = wspb.Write(ctx, conn, &handshake)
	require.NoError(d.t, err)

	// Receive/check the handshake
	var handshakeResult proxy.HandshakeResult
	err = wspb.Read(ctx, conn, &handshakeResult)
	if expectExpired {
		require.Contains(d.t, err.Error(), "tofu token not allowed")
		return nil
	} else {
		require.NoError(d.t, err)
	}
	// This is just a cursory check to make sure that the handshake is
	// populated. We could check connections remaining too, but that
	// could legitimately be a trivial (zero) value.
	require.NotNil(d.t, handshakeResult.GetExpiration())

	return websocket.NetConn(ctx, conn, websocket.MessageBinary)
}

type testTcpServer struct {
	t     *testing.T // For logging
	ln    net.Listener
	conns map[string]net.Conn
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
				ts.t.Logf("Accept() error in testTcpServer: %s", err)
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

func newTestTcpServer(t *testing.T) *testTcpServer {
	t.Helper()

	ts := &testTcpServer{
		t:     t,
		conns: make(map[string]net.Conn),
	}
	var err error
	ts.ln, err = net.Listen("tcp", ":0")
	require.NoError(t, err)

	go ts.run()
	return ts
}
