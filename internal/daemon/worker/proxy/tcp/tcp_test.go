package tcp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/worker/proxy"
	"github.com/hashicorp/boundary/internal/daemon/worker/session"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/targets"
	"github.com/hashicorp/boundary/sdk/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
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
	sessClient.LookupSessionFn = func(_ context.Context, request *pbs.LookupSessionRequest) (*pbs.LookupSessionResponse, error) {
		cert, _, _ := createTestCert(t)
		return &pbs.LookupSessionResponse{
			Authorization: &targets.SessionAuthorizationData{
				SessionId:   request.GetSessionId(),
				Certificate: cert,
			},
			Expiration: timestamppb.New(time.Now().Add(time.Hour)),
		}, nil
	}
	sessClient.AuthorizeConnectionFn = func(_ context.Context, req *pbs.AuthorizeConnectionRequest) (*pbs.AuthorizeConnectionResponse, error) {
		return &pbs.AuthorizeConnectionResponse{
			ConnectionId:    "mock-connection",
			Status:          pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_AUTHORIZED,
			ConnectionsLeft: -1,
		}, nil
	}
	sessClient.ConnectConnectionFn = func(_ context.Context, _ *pbs.ConnectConnectionRequest) (*pbs.ConnectConnectionResponse, error) {
		return &pbs.ConnectConnectionResponse{
			Status: pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CONNECTED,
		}, nil
	}
	manager, err := session.NewManager(sessClient)
	require.NoError(err)
	s, err := manager.LoadLocalSession(ctx, "one", "workerid")
	require.NoError(err)
	_, connCancelFn := context.WithCancel(context.Background())
	_, _, err = s.RequestAuthorizeConnection(ctx, "workerid", connCancelFn)
	require.NoError(err)

	conn := websocket.NetConn(ctx, proxyConn, websocket.MessageBinary)
	conf := proxy.Config{
		ClientAddress:  clientAddr,
		ClientConn:     conn,
		RemoteEndpoint: fmt.Sprintf("tcp://localhost:%d", port),
		Session:        s,
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

func createTestCert(t *testing.T) ([]byte, ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign,
		SerialNumber:          big.NewInt(0),
		NotBefore:             time.Now().Add(-30 * time.Second),
		NotAfter:              time.Now().Add(5 * time.Minute),
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"/tmp/boundary-opslistener-test0.sock", "/tmp/boundary-opslistener-test1.sock"},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	require.NoError(t, err)

	return certBytes, pub, priv
}
