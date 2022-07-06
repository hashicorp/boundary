package proxy

import (
	"context"
	"net"
	"testing"

	"github.com/hashicorp/boundary/internal/daemon/worker/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"nhooyr.io/websocket"
)

type testSession struct {
	session.Session
}

func TestConfigValidate(t *testing.T) {
	t.Parallel()

	// Create mock data for session management section of HandleTcpProxyV1
	clientAddr := &net.TCPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 50000,
	}
	si := testSession{}
	conn := &websocket.Conn{}

	tests := []struct {
		name       string
		conf       Config
		wantErr    bool
		wantErrMsg string
	}{
		{
			name: "missing-client-address",
			conf: Config{
				ClientConn:     conn,
				RemoteEndpoint: "tcp://remote",
				Session:        si,
				ConnectionId:   "connection-id",
			},
			wantErr:    true,
			wantErrMsg: "missing client address",
		},
		{
			name: "missing-client-conn",
			conf: Config{
				ClientAddress:  clientAddr,
				RemoteEndpoint: "tcp://remote",
				Session:        si,
				ConnectionId:   "connection-id",
			},
			wantErr:    true,
			wantErrMsg: "missing client connection",
		},
		{
			name: "missing-remote-endpoint",
			conf: Config{
				ClientAddress: clientAddr,
				ClientConn:    conn,
				Session:       si,
				ConnectionId:  "connection-id",
			},
			wantErr:    true,
			wantErrMsg: "missing remote endpoint",
		},
		{
			name: "missing-session",
			conf: Config{
				ClientAddress:  clientAddr,
				ClientConn:     conn,
				RemoteEndpoint: "tcp://remote",
				ConnectionId:   "connection-id",
			},
			wantErr:    true,
			wantErrMsg: "missing session",
		},
		{
			name: "missing-connection-id",
			conf: Config{
				ClientAddress:  clientAddr,
				ClientConn:     conn,
				RemoteEndpoint: "tcp://remote",
				Session:        si,
			},
			wantErr:    true,
			wantErrMsg: "missing connection id",
		},
		{
			name: "valid",
			conf: Config{
				ClientAddress:  clientAddr,
				ClientConn:     conn,
				RemoteEndpoint: "tcp://remote",
				Session:        si,
				ConnectionId:   "connection-id",
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			err := tt.conf.Validate()
			if tt.wantErr {
				require.Error(err)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			require.NoError(err)
		})
	}
}

func TestRegisterHandler(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)

	fn := func(context.Context, Config, ...Option) error { return nil }

	err := RegisterHandler("protocol", fn)
	require.NoError(err)

	// Register function with same protocol
	err = RegisterHandler("protocol", fn)
	require.Error(err)
	assert.ErrorIs(err, ErrProtocolAlreadyRegistered)

	err = RegisterHandler("new-protocol", fn)
	require.NoError(err)
}

func TestGetHandler(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)

	fn := func(context.Context, Config, ...Option) error { return nil }

	err := RegisterHandler("fn", fn)
	require.NoError(err)

	gotFn, err := GetHandler("fake")
	require.Error(err)
	assert.ErrorIs(err, ErrUnknownProtocol)
	assert.Nil(gotFn)

	gotFn, err = GetHandler("fn")
	require.NoError(err)
	assert.NotNil(gotFn)
}
