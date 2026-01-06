// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package sequential

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/daemon/worker"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/tests/helper"
	"github.com/hashicorp/dawdle"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

func TestWorkerSessionProxyMultipleConnections(t *testing.T) {
	const op = "cluster.TestWorkerSessionMultipleConnections"

	// This prevents us from running tests in parallel.
	server.TestUseCommunityFilterWorkersFn(t)

	require := require.New(t)
	logger := hclog.New(&hclog.LoggerOptions{
		Name:  t.Name(),
		Level: hclog.Trace,
	})

	pl, err := net.Listen("tcp", "[::1]:")
	require.NoError(err)

	conf, err := config.DevController(config.WithIPv6Enabled(true))
	require.NoError(err)

	// update cluster listener to utilize proxy listener address
	for _, l := range conf.Listeners {
		if l.Purpose[0] == "cluster" {
			l.Address = pl.Addr().String()
		}
	}

	c1 := controller.NewTestController(t, &controller.TestControllerOpts{
		Config:                  conf,
		InitialResourcesSuffix:  "1234567890",
		Logger:                  logger.Named("c1"),
		WorkerRPCGracePeriod:    helper.DefaultControllerRPCGracePeriod,
		SchedulerRunJobInterval: 500 * time.Millisecond,
	})

	helper.ExpectWorkers(t, c1)

	// Wire up the testing proxies
	require.Len(c1.ClusterAddrs(), 1)
	proxy, err := dawdle.NewProxy("tcp", "", c1.ClusterAddrs()[0],
		dawdle.WithListener(pl),
		dawdle.WithRbufSize(256),
		dawdle.WithWbufSize(256),
	)
	require.NoError(err)
	t.Cleanup(func() { _ = proxy.Close() })
	require.NotEmpty(t, proxy.ListenerAddr())

	w1 := worker.NewTestWorker(t, &worker.TestWorkerOpts{
		WorkerAuthKms:    c1.Config().WorkerAuthKms,
		InitialUpstreams: []string{proxy.ListenerAddr()},
		Logger:           logger.Named("w1"),
		SuccessfulControllerRPCGracePeriodDuration: helper.DefaultControllerRPCGracePeriod,
		EnableIPv6:        true,
		WorkerRPCInterval: 500 * time.Millisecond,
	})

	helper.ExpectWorkers(t, c1, w1)

	// Use an independent context for test things that take a context so
	// that we aren't tied to any timeouts in the controller, etc. This
	// can interfere with some of the test operations.
	ctx := context.Background()

	// Connect target
	client := c1.Client()
	client.SetToken(c1.Token().Token)
	tcl := targets.NewClient(client)
	tgt, err := tcl.Read(ctx, "ttcp_1234567890")
	require.NoError(err)
	require.NotNil(tgt)

	// Create test server, update default port on target
	ts := helper.NewTestTcpServer(t)
	require.NotNil(t, ts)
	t.Cleanup(ts.Close)
	t.Logf("test server listening on port %d", ts.Port())

	tgt, err = tcl.Update(ctx, tgt.Item.Id, tgt.Item.Version, targets.WithTcpTargetDefaultPort(ts.Port()), targets.WithSessionConnectionLimit(-1))
	require.NoError(err)
	require.NotNil(tgt)

	// Authorize and connect
	workerInfo := []*targets.WorkerInfo{
		{
			Address: w1.ProxyAddrs()[0],
		},
	}
	sess := helper.NewTestSession(ctx, t, tcl, "ttcp_1234567890", helper.WithWorkerInfo(workerInfo))
	sConn := sess.Connect(ctx, t)

	// Run initial send/receive test, make sure things are working
	event.WriteSysEvent(ctx, op, "running initial send/recv test for initial connection")
	sConn.TestSendRecvAll(t)

	// Create another connection for this session
	sConn2 := sess.Connect(ctx, t)
	// Ensure second connection works
	event.WriteSysEvent(ctx, op, "running initial send/recv test for second connection")
	sConn2.TestSendRecvAll(t)

	// Create another connection for this session
	sConn3 := sess.Connect(ctx, t)
	// Ensure second connection works
	event.WriteSysEvent(ctx, op, "running initial send/recv test for third connection")
	sConn3.TestSendRecvAll(t)
}
