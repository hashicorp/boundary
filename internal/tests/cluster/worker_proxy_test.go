// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cluster

import (
	"context"
	"net"
	"testing"

	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	tg "github.com/hashicorp/boundary/internal/daemon/controller/handlers/targets"
	"github.com/hashicorp/boundary/internal/daemon/worker"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/tests/helper"
	"github.com/hashicorp/dawdle"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

func TestWorkerSessionProxyMultipleConnections(t *testing.T) {
	const op = "cluster.TestWorkerSessionMultipleConnections"

	// This prevents us from running tests in parallel.
	tg.SetupSuiteTargetFilters(t)

	require := require.New(t)
	logger := hclog.New(&hclog.LoggerOptions{
		Name:  t.Name(),
		Level: hclog.Trace,
	})

	conf, err := config.DevController()
	require.NoError(err)

	pl, err := net.Listen("tcp", "localhost:0")
	require.NoError(err)
	c1 := controller.NewTestController(t, &controller.TestControllerOpts{
		Config:                          conf,
		InitialResourcesSuffix:          "1234567890",
		Logger:                          logger.Named("c1"),
		PublicClusterAddr:               pl.Addr().String(),
		WorkerStatusGracePeriodDuration: helper.DefaultWorkerStatusGracePeriod,
	})
	defer c1.Shutdown()

	ExpectWorkers(t, c1)

	// Wire up the testing proxies
	require.Len(c1.ClusterAddrs(), 1)
	proxy, err := dawdle.NewProxy("tcp", "", c1.ClusterAddrs()[0],
		dawdle.WithListener(pl),
		dawdle.WithRbufSize(256),
		dawdle.WithWbufSize(256),
	)
	require.NoError(err)
	defer proxy.Close()
	require.NotEmpty(t, proxy.ListenerAddr())

	w1 := worker.NewTestWorker(t, &worker.TestWorkerOpts{
		WorkerAuthKms:                       c1.Config().WorkerAuthKms,
		InitialUpstreams:                    []string{proxy.ListenerAddr()},
		Logger:                              logger.Named("w1"),
		SuccessfulStatusGracePeriodDuration: helper.DefaultWorkerStatusGracePeriod,
	})
	defer w1.Shutdown()

	err = w1.Worker().WaitForNextSuccessfulStatusUpdate()
	require.NoError(err)
	err = c1.WaitForNextWorkerStatusUpdate(w1.Name())
	require.NoError(err)
	ExpectWorkers(t, c1, w1)

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
	defer ts.Close()
	tgt, err = tcl.Update(ctx, tgt.Item.Id, tgt.Item.Version, targets.WithTcpTargetDefaultPort(ts.Port()), targets.WithSessionConnectionLimit(-1))
	require.NoError(err)
	require.NotNil(tgt)

	// Authorize and connect
	sess := helper.NewTestSession(ctx, t, tcl, "ttcp_1234567890")
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
