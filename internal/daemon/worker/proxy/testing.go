// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWsConn creates a websocket client and handler simulating the local websocket proxy
// created during Boundary connect. The proxyConn returned should be used as the connection
// passed into the worker proxy handler, while the clientConn can be used to simulate
// the local end user connection.
func TestWsConn(t testing.TB, ctx context.Context) (clientConn, proxyConn *websocket.Conn) {
	t.Helper()
	require, assert := require.New(t), assert.New(t)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(err)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		err := http.Serve(l, http.HandlerFunc(
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

	time.Sleep(time.Duration(1.5 * float64(time.Second)))
	clientConn, _, err = websocket.Dial(ctx, fmt.Sprintf("ws://%s", l.Addr().String()), nil)
	require.NoError(err)
	t.Cleanup(func() { _ = clientConn.Close(websocket.StatusGoingAway, "done") })
	wg.Wait()
	return clientConn, proxyConn
}
