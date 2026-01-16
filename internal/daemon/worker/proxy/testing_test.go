// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package proxy

import (
	"context"
	"testing"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type connMsg struct {
	msg []byte
	err error
}

func Test_TestWsConn(t *testing.T) {
	t.Parallel()
	require, assert := require.New(t), assert.New(t)

	ctx, cancelCtx := context.WithCancel(context.Background())
	clientConn, proxyConn := TestWsConn(t, ctx)

	// Use msg channel so that we can use test assertions on the returned content.
	// It is illegal to call `t.FailNow()` from a goroutine.
	// https://pkg.go.dev/testing#T.FailNow
	readChan := make(chan connMsg)
	go func() {
		_, msg, err := proxyConn.Read(ctx)
		readChan <- connMsg{msg, err}
	}()

	err := clientConn.Write(ctx, websocket.MessageBinary, []byte("client to proxy"))
	require.NoError(err)

	// Wait for read to verify success
	msg := <-readChan
	require.NoError(msg.err)
	assert.Equal("client to proxy", string(msg.msg))

	go func() {
		_, msg, err := clientConn.Read(ctx)
		readChan <- connMsg{msg, err}
	}()

	err = proxyConn.Write(ctx, websocket.MessageBinary, []byte("proxy to client"))
	require.NoError(err)

	// Wait for read to verify success
	msg = <-readChan
	require.NoError(msg.err)
	assert.Equal("proxy to client", string(msg.msg))

	cancelCtx()
}
