package proxy

import (
	"context"
	"net"
	"testing"

	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/servers/worker/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"nhooyr.io/websocket"
)

func TestConfigValidate(t *testing.T) {
	t.Parallel()

	// Create mock data for session management section of HandleTcpProxyV1
	clientAddr := &net.TCPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 50000,
	}
	sessClient := pbs.NewMockSessionServiceClient()
	si := &session.Info{
		Id: "one",
	}
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
				SessionClient:  sessClient,
				SessionInfo:    si,
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
				SessionClient:  sessClient,
				SessionInfo:    si,
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
				SessionClient: sessClient,
				SessionInfo:   si,
				ConnectionId:  "connection-id",
			},
			wantErr:    true,
			wantErrMsg: "missing remote endpoint",
		},
		{
			name: "missing-session-client",
			conf: Config{
				ClientAddress:  clientAddr,
				ClientConn:     conn,
				RemoteEndpoint: "tcp://remote",
				SessionInfo:    si,
				ConnectionId:   "connection-id",
			},
			wantErr:    true,
			wantErrMsg: "missing session client",
		},
		{
			name: "missing-session-info",
			conf: Config{
				ClientAddress:  clientAddr,
				ClientConn:     conn,
				RemoteEndpoint: "tcp://remote",
				SessionClient:  sessClient,
				ConnectionId:   "connection-id",
			},
			wantErr:    true,
			wantErrMsg: "missing session info",
		},
		{
			name: "missing-connection-id",
			conf: Config{
				ClientAddress:  clientAddr,
				ClientConn:     conn,
				RemoteEndpoint: "tcp://remote",
				SessionClient:  sessClient,
				SessionInfo:    si,
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
				SessionClient:  sessClient,
				SessionInfo:    si,
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

	fn := func(context.Context, Config, ...Option) { return }

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

	fn := func(context.Context, Config, ...Option) {}

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
