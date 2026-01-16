// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package proxy

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api/proxy"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/daemon/worker"
	"github.com/hashicorp/boundary/internal/tests/helper"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
	"go.uber.org/atomic"

	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/targets/tcp"
)

var updateTargetForProxy = func(t *testing.T, ctx context.Context, c *targets.Client, tgt *targets.TargetReadResult, port uint32, connLimit int32, workerName string) *targets.TargetReadResult {
	t.Helper()
	ret, err := c.Update(ctx, tgt.Item.Id, tgt.Item.Version,
		targets.WithTcpTargetDefaultPort(port),
		targets.WithSessionConnectionLimit(connLimit),
	)
	require.NoError(t, err)
	require.NotNil(t, ret)
	return ret
}

// TestConnectionsLeft tests general proxy functionality, as well as the
// mechanism to notify the caller of the number of connections left on the
// caller's channel and in the ConnectionsLeft function.
func TestConnectionsLeft(t *testing.T) {
	require := require.New(t)
	logger := hclog.New(&hclog.LoggerOptions{
		Name:  t.Name(),
		Level: hclog.Trace,
	})

	// Create controller and worker
	conf, err := config.DevController()
	require.NoError(err)
	c1 := controller.NewTestController(t, &controller.TestControllerOpts{
		Config:                 conf,
		InitialResourcesSuffix: "1234567890",
		Logger:                 logger.Named("c1"),
		WorkerRPCGracePeriod:   helper.DefaultControllerRPCGracePeriod,
	})
	helper.ExpectWorkers(t, c1)

	w1 := worker.NewTestWorker(t, &worker.TestWorkerOpts{
		WorkerAuthKms:    c1.Config().WorkerAuthKms,
		InitialUpstreams: c1.ClusterAddrs(),
		Logger:           logger.Named("w1"),
		SuccessfulControllerRPCGracePeriodDuration: helper.DefaultControllerRPCGracePeriod,
		Name: "w1",
	})
	helper.ExpectWorkers(t, c1, w1)

	// Connect target
	client := c1.Client()
	client.SetToken(c1.Token().Token)
	tcl := targets.NewClient(client)
	tgt, err := tcl.Read(c1.Context(), "ttcp_1234567890")
	require.NoError(err)
	require.NotNil(tgt)

	// Create test server, update default port on target
	ts := helper.NewTestTcpServer(t)
	require.NotNil(t, ts)
	defer ts.Close()
	var sessionConnsLimit int32 = 4

	tgt = updateTargetForProxy(t, c1.Context(), tcl, tgt, ts.Port(), sessionConnsLimit, w1.Name())

	// Authorize session to get authorization data
	sess, err := tcl.AuthorizeSession(c1.Context(), tgt.Item.Id)
	require.NoError(err)
	sessAuthz, err := sess.GetSessionAuthorization()
	require.NoError(err)

	// Create a context we can cancel to stop the proxy, a channel for conns
	// left, and a waitgroup to ensure cleanup
	pxyCtx, pxyCancel := context.WithCancel(c1.Context())
	defer pxyCancel()
	connsLeftCh := make(chan int32)
	wg := new(sync.WaitGroup)

	pxy, err := proxy.New(pxyCtx, sessAuthz.AuthorizationToken, proxy.WithConnectionsLeftCh(connsLeftCh))
	require.NoError(err)
	wg.Add(1)
	go func() {
		defer wg.Done()
		require.NoError(pxy.Start())
		// Ensure that starting it again does not actually result in it starting
		// again
		require.ErrorContains(pxy.Start(), "already started")
	}()

	addr := pxy.ListenerAddress(context.Background())
	require.NotEmpty(addr)
	addrPort, err := netip.ParseAddrPort(addr)
	require.NoError(err)

	echo := []byte("echo")
	readBuf := make([]byte, len(echo))
	// While we have sessions left, expect no error and to read and write
	// through the proxy, and to read the conns left from the channel. Once we
	// have hit the connection limit, we expect an error on dial.
	for i := sessionConnsLimit; i >= 0; i-- {
		// Give time for the listener to be closed. The information about conns
		// left comes from upstream responses and we can circle around too fast
		// to have the listener be closed, leading to indeterminate results.
		time.Sleep(time.Second)
		conn, err := net.DialTCP("tcp", nil, net.TCPAddrFromAddrPort(addrPort))
		if i == 0 {
			require.Error(err)
			break
		}
		require.NoError(err)
		written, err := conn.Write(echo)
		require.NoError(err)
		require.Equal(written, len(echo))
		read, err := conn.Read(readBuf)
		require.NoError(err)
		require.Equal(read, len(echo))
		connsLeft := <-connsLeftCh
		require.Equal(i-1, connsLeft)
		require.Equal(i-1, pxy.ConnectionsLeft())
	}

	pxyCancel()
	// Wait to ensure cleanup and that the second-start logic works
	wg.Wait()
}

func TestConnectionTimeout(t *testing.T) {
	require := require.New(t)
	logger := hclog.New(&hclog.LoggerOptions{
		Name:  t.Name(),
		Level: hclog.Trace,
	})

	// Create controller and worker
	conf, err := config.DevController()
	require.NoError(err)
	c1 := controller.NewTestController(t, &controller.TestControllerOpts{
		Config:                 conf,
		InitialResourcesSuffix: "1234567890",
		Logger:                 logger.Named("c1"),
		WorkerRPCGracePeriod:   helper.DefaultControllerRPCGracePeriod,
	})
	helper.ExpectWorkers(t, c1)

	w1 := worker.NewTestWorker(t, &worker.TestWorkerOpts{
		WorkerAuthKms:    c1.Config().WorkerAuthKms,
		InitialUpstreams: c1.ClusterAddrs(),
		Logger:           logger.Named("w1"),
		SuccessfulControllerRPCGracePeriodDuration: helper.DefaultControllerRPCGracePeriod,
		Name: "w1",
	})
	helper.ExpectWorkers(t, c1, w1)

	// Connect target
	client := c1.Client()
	client.SetToken(c1.Token().Token)
	tcl := targets.NewClient(client)
	tgt, err := tcl.Read(c1.Context(), "ttcp_1234567890")
	require.NoError(err)
	require.NotNil(tgt)

	// Create test server, update default port on target
	ts := helper.NewTestTcpServer(t)
	require.NotNil(t, ts)
	defer ts.Close()
	var sessionConnsLimit int32 = 2

	tgt = updateTargetForProxy(t, c1.Context(), tcl, tgt, ts.Port(), sessionConnsLimit, w1.Name())

	// Authorize session to get authorization data
	sess, err := tcl.AuthorizeSession(c1.Context(), tgt.Item.Id)
	require.NoError(err)
	sessAuthz, err := sess.GetSessionAuthorization()
	require.NoError(err)

	// Create a context we can cancel to stop the proxy, a channel for conns
	// left, and a waitgroup to ensure cleanup
	pxyCtx, pxyCancel := context.WithCancel(c1.Context())
	defer pxyCancel()
	wg := new(sync.WaitGroup)

	pxy, err := proxy.New(pxyCtx, sessAuthz.AuthorizationToken)
	require.NoError(err)
	wg.Add(1)
	done := atomic.NewBool(false)
	go func() {
		defer wg.Done()
		require.NoError(pxy.Start(proxy.WithInactivityTimeout(time.Second)))
		done.Store(true)
	}()

	addr := pxy.ListenerAddress(context.Background())
	require.NotEmpty(addr)
	addrPort, err := netip.ParseAddrPort(addr)
	require.NoError(err)

	echo := []byte("echo")
	readBuf := make([]byte, len(echo))

	conn, err := net.DialTCP("tcp", nil, net.TCPAddrFromAddrPort(addrPort))
	require.NoError(err)
	written, err := conn.Write(echo)
	require.NoError(err)
	require.Equal(written, len(echo))
	read, err := conn.Read(readBuf)
	require.NoError(err)
	require.Equal(read, len(echo))
	require.NoError(conn.Close())

	start := time.Now()
	for {
		if done.Load() || time.Since(start) > time.Second*2 {
			require.True(done.Load(), "proxy did not close itself within the expected time frame (2 seconds)")
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	require.Equal("Inactivity timeout reached", pxy.CloseReason())
	pxyCancel()
	wg.Wait()
}
