package tcp

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"testing"

	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/targets"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/servers/worker/session"
	"github.com/hashicorp/boundary/sdk/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"nhooyr.io/websocket"
)

func testWsConn(t *testing.T, ctx context.Context) (clientConn, proxyConn *websocket.Conn) {
	t.Helper()
	require, assert := require.New(t), assert.New(t)

	var wg sync.WaitGroup
	wg.Add(1)
	port := testutil.TestFreePort(t)
	go func() {
		err := http.ListenAndServe(fmt.Sprintf(":%d", port), http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				var err error

				proxyConn, err = websocket.Accept(w, r, nil)
				require.NoError(err)

				wg.Done()
				// block waiting for test to complete
				select {
				case <-ctx.Done():
				}
			}))
		assert.NoError(err)
	}()

	clientConn, _, err := websocket.Dial(ctx, fmt.Sprintf("ws://localhost:%d", port), nil)
	require.NoError(err)
	wg.Wait()
	return
}

func TestHandleTcpProxyV1(t *testing.T) {
	require, assert := require.New(t), assert.New(t)

	ctx, cancelCtx := context.WithCancel(context.Background())
	clientConn, proxyConn := testWsConn(t, ctx)

	port := testutil.TestFreePort(t)
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	require.NoError(err)
	defer l.Close()

	var endpointConn net.Conn
	ready := make(chan struct{})
	go func() {
		endpointConn, err = l.Accept()
		require.NoError(err)

		defer endpointConn.Close()
		ready <- struct{}{}

		// block waiting for test to complete
		select {
		case <-ctx.Done():
		}
	}()

	// Create mock data for session management section of HandleTcpProxyV1
	clientAddr := &net.TCPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 50000,
	}
	sessClient := pbs.NewMockSessionServiceClient()
	si := &session.Info{
		Id: "one",
		LookupSessionResponse: &pbs.LookupSessionResponse{
			Authorization: &targets.SessionAuthorizationData{
				SessionId: "mock-session",
			},
		},
		ConnInfoMap: map[string]*session.ConnInfo{
			"mock-connection": {},
		},
	}

	go HandleTcpProxyV1(ctx, clientAddr, proxyConn, nil, sessClient, si, "mock-connection", fmt.Sprintf("tcp://localhost:%d", port))

	// wait for HandleTcpProxyV1 to dial endpoint
	<-ready
	netConn := websocket.NetConn(ctx, clientConn, websocket.MessageBinary)

	// Write from endpoint to client
	writeLen, err := endpointConn.Write([]byte("endpoint write to client via proxy"))
	require.NoError(err)

	b := make([]byte, writeLen)
	readLen, err := netConn.Read(b)
	require.NoError(err)
	assert.Equal(writeLen, readLen)
	assert.Equal("endpoint write to client via proxy", string(b))

	// Write from client to endpoint
	writeLen, err = netConn.Write([]byte("client write to endpoint via proxy"))
	require.NoError(err)

	b1 := make([]byte, writeLen)
	readLen, err = endpointConn.Read(b1)
	require.NoError(err)
	assert.Equal(writeLen, readLen)
	assert.Equal("client write to endpoint via proxy", string(b1))

	cancelCtx()
}
