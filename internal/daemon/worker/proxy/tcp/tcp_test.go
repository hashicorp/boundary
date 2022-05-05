package tcp

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/hashicorp/boundary/internal/daemon/worker/proxy"
	"github.com/hashicorp/boundary/internal/daemon/worker/session"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/targets"
	"github.com/hashicorp/boundary/sdk/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"nhooyr.io/websocket"
)

func TestHandleTcpProxyV1(t *testing.T) {
	t.Parallel()
	require, assert := require.New(t), assert.New(t)

	ctx, cancelCtx := context.WithCancel(context.Background())
	clientConn, proxyConn := proxy.TestWsConn(t, ctx)
	require.NotNil(clientConn)
	require.NotNil(proxyConn)

	port := testutil.TestFreePort(t)
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	require.NoError(err)
	defer l.Close()

	var endpointConn net.Conn
	var endpointErr error
	ready := make(chan struct{})
	go func() {
		endpointConn, endpointErr = l.Accept()

		defer endpointConn.Close()
		ready <- struct{}{}

		// block waiting for test to complete
		<-ctx.Done()
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

	conf := proxy.Config{
		ClientAddress:  clientAddr,
		ClientConn:     proxyConn,
		RemoteEndpoint: fmt.Sprintf("tcp://localhost:%d", port),
		SessionClient:  sessClient,
		SessionInfo:    si,
		ConnectionId:   "mock-connection",
		UserClientIp:   net.ParseIP("127.0.0.1"),
	}

	// Use error channel so that we can use test assertions on the returned error.
	// It is illegal to call `t.FailNow()` from a goroutine.
	// https://pkg.go.dev/testing#T.FailNow
	errChan := make(chan error)
	go func() {
		errChan <- handleProxy(ctx, conf)
	}()
	t.Cleanup(func() {
		require.NoError(<-errChan)
	})

	// wait for HandleTcpProxyV1 to dial endpoint
	<-ready
	require.NoError(endpointErr)
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
