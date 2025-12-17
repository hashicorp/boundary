// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package tcp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/boundary/internal/daemon/worker/proxy"
	"github.com/hashicorp/boundary/internal/daemon/worker/session"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/targets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestHandleProxy_Errors(t *testing.T) {
	c, _ := net.Pipe()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		l.Close()
	})
	dialer, err := proxy.NewProxyDialer(context.Background(), func(...proxy.Option) (net.Conn, error) {
		return net.Dial("tcp", l.Addr().String())
	})
	require.NoError(t, err)

	cases := []struct {
		name        string
		conn        net.Conn
		dialer      *proxy.ProxyDialer
		connId      string
		protocolCtx *anypb.Any
		wantError   bool
	}{
		{
			name:        "valid",
			conn:        c,
			dialer:      dialer,
			connId:      "someconnectionid",
			protocolCtx: nil,
			wantError:   false,
		},
		{
			name:        "nil connection",
			dialer:      dialer,
			connId:      "someconnectionid",
			protocolCtx: nil,
			wantError:   true,
		},
		{
			name:        "nil dialer",
			conn:        c,
			connId:      "someconnectionid",
			protocolCtx: nil,
			wantError:   true,
		},
		{
			name:        "no connection id",
			conn:        c,
			dialer:      dialer,
			protocolCtx: nil,
			wantError:   true,
		},
		{
			name:   "specified protocol context passed on without validation",
			conn:   c,
			dialer: dialer,
			connId: "someconnectionid",
			protocolCtx: &anypb.Any{
				TypeUrl: "some.type.information",
				Value:   []byte("this is just for this test"),
			},
			wantError: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			fn, err := handleProxy(ctx, ctx, nil, tc.conn, tc.dialer, tc.connId, tc.protocolCtx, nil)
			if tc.wantError {
				assert.Error(t, err)
				assert.Nil(t, fn)
				return
			}
			assert.NoError(t, err)
			assert.NotNil(t, fn)
		})
	}
}

func TestHandleTcpProxyV1(t *testing.T) {
	t.Parallel()
	require, assert := require.New(t), assert.New(t)

	ctx, cancelCtx := context.WithCancel(context.Background())
	clientConn, proxyConn := proxy.TestWsConn(t, ctx)
	require.NotNil(clientConn)
	require.NotNil(proxyConn)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(err)
	defer l.Close()

	var endpointConn net.Conn
	var endpointErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		endpointConn, endpointErr = l.Accept()
		require.NoError(endpointErr)
		defer endpointConn.Close()

		wg.Done()
		// block waiting for test to complete
		<-ctx.Done()
	}()

	// Create mock data for session management section of HandleTcpProxyV1
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
	resp, _, err := s.RequestAuthorizeConnection(ctx, "workerid", connCancelFn)
	require.NoError(err)

	tDial, err := proxy.NewProxyDialer(ctx, func(...proxy.Option) (net.Conn, error) {
		return net.Dial("tcp", l.Addr().String())
	})
	require.NoError(err)
	conn := websocket.NetConn(ctx, proxyConn, websocket.MessageBinary)

	go func() {
		fn, err := handleProxy(ctx, context.Background(), nil, conn, tDial, resp.GetConnectionId(), resp.GetProtocolContext(), nil)
		t.Cleanup(func() {
			// Use of the t.Cleanup is so we can check the state of the returned
			// error since it isn't valid to call `t.FailNow()` from a goroutine.
			// https://pkg.go.dev/testing#T.FailNow
			require.NoError(err)
		})
		fn()
	}()

	// wait for HandleTcpProxyV1 to dial endpoint
	wg.Wait()
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
