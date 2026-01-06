// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package parallel

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/daemon/worker"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/tests/helper"
	"github.com/hashicorp/dawdle"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

// TestSpeedyOrphanedConnectionCleanup tests that we successfully
// clean up connections that are orphaned to a worker that never
// successfully reported a session info.
func TestSpeedyOrphanedConnectionCleanup(t *testing.T) {
	t.Parallel()
	logger := hclog.New(&hclog.LoggerOptions{
		Name:  t.Name(),
		Level: hclog.Trace,
	})

	conf, err := config.DevController()
	require.NoError(t, err)

	pl, err := net.Listen("tcp", "[::1]:0")
	require.NoError(t, err)
	c := controller.NewTestController(t, &controller.TestControllerOpts{
		Config:                 conf,
		InitialResourcesSuffix: "1234567890",
		Logger:                 logger.Named("c1"),
		PublicClusterAddr:      pl.Addr().String(),
		WorkerRPCGracePeriod:   10 * time.Second,
		// Run the scheduler more often to speed up cleanup of orphaned connections
		SchedulerRunJobInterval: 500 * time.Millisecond,
	})

	helper.ExpectWorkers(t, c)

	// Wire up the testing proxies
	require.Len(t, c.ClusterAddrs(), 1)
	proxy, err := dawdle.NewProxy("tcp", "", c.ClusterAddrs()[0],
		dawdle.WithListener(pl),
		dawdle.WithRbufSize(256),
		dawdle.WithWbufSize(256),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = proxy.Close()
	})
	require.NotEmpty(t, proxy.ListenerAddr())

	w := worker.NewTestWorker(t, &worker.TestWorkerOpts{
		WorkerAuthKms:    c.Config().WorkerAuthKms,
		InitialUpstreams: []string{proxy.ListenerAddr()},
		Logger:           logger.Named("w1"),
		SuccessfulControllerRPCGracePeriodDuration: 10 * time.Second,
		WorkerRPCInterval:                          500 * time.Millisecond,
	})

	helper.ExpectWorkers(t, c, w)

	// Use an independent context for test things that take a context so
	// that we aren't tied to any timeouts in the controller, etc. This
	// can interfere with some of the test operations.
	ctx := context.Background()

	// Connect target
	client := c.Client()
	client.SetToken(c.Token().Token)
	tcl := targets.NewClient(client)
	tgt, err := tcl.Read(ctx, "ttcp_1234567890")
	require.NoError(t, err)
	require.NotNil(t, tgt)

	// Create test server, update default port on target
	ts := helper.NewTestTcpServer(t)
	require.NotNil(t, ts)
	t.Cleanup(ts.Close)
	tgt, err = tcl.Update(ctx, tgt.Item.Id, tgt.Item.Version, targets.WithTcpTargetDefaultPort(ts.Port()), targets.WithSessionConnectionLimit(-1))
	require.NoError(t, err)
	require.NotNil(t, tgt)

	// Authorize and connect
	sess := helper.NewTestSession(ctx, t, tcl, "ttcp_1234567890")
	sConn := sess.Connect(ctx, t)

	// Run initial send/receive test, make sure things are working
	t.Log("running initial send/recv test")
	sConn.TestSendRecvAll(t)

	// Kill the link before the worker has a chance to send a session info
	t.Log("pausing controller/worker link")
	proxy.Pause()
	t.Cleanup(proxy.Resume) // Resume the proxy on cleanup to allow other cleanup to run

	// Both the worker and the controller should detect that the worker is dead
	// and close the connection.
	sess.ExpectConnectionStateOnWorker(ctx, t, w, session.StatusClosed)
	sess.ExpectConnectionStateOnController(ctx, t, c.Controller().ConnectionRepoFn, session.StatusClosed)
}
