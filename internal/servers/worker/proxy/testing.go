package proxy

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/sdk/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"nhooyr.io/websocket"
)

// TestWsConn creates a websocket client and handler simulating the local websocket proxy
// created during Boundary connect. The proxyConn returned should be used as the connection
// passed into the worker proxy handler, while the clientConn can be used to simulate
// the local end user connection.
func TestWsConn(t testing.TB, ctx context.Context) (clientConn, proxyConn *websocket.Conn) {
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

	time.Sleep(time.Duration(1.5 * float64(time.Second)))
	clientConn, _, err := websocket.Dial(ctx, fmt.Sprintf("ws://localhost:%d", port), nil)
	require.NoError(err)
	wg.Wait()
	return
}
