package proxy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"nhooyr.io/websocket"
)

func Test_TestWsConn(t *testing.T) {
	t.Parallel()
	require, assert := require.New(t), assert.New(t)

	ctx, cancelCtx := context.WithCancel(context.Background())
	clientConn, proxyConn := TestWsConn(t, ctx)

	successfulRead := make(chan struct{})
	go func() {
		_, msg, err := proxyConn.Read(ctx)
		require.NoError(err)
		assert.Equal("client to proxy", string(msg))
		successfulRead <- struct{}{}
	}()

	err := clientConn.Write(ctx, websocket.MessageBinary, []byte("client to proxy"))
	require.NoError(err)

	// Wait for read to verify success
	<-successfulRead

	go func() {
		_, msg, err := clientConn.Read(ctx)
		require.NoError(err)
		assert.Equal("proxy to client", string(msg))
		successfulRead <- struct{}{}
	}()

	err = proxyConn.Write(ctx, websocket.MessageBinary, []byte("proxy to client"))
	require.NoError(err)

	// Wait for read to verify success
	<-successfulRead

	cancelCtx()
}
