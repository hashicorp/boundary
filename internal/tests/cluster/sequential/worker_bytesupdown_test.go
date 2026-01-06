// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package sequential

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/daemon/worker"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/tests/helper"
	"github.com/hashicorp/dawdle"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

func TestWorkerBytesUpDown(t *testing.T) {
	require := require.New(t)

	// This prevents us from running tests in parallel.
	server.TestUseCommunityFilterWorkersFn(t)

	logger := hclog.New(&hclog.LoggerOptions{
		Name:  t.Name(),
		Level: hclog.Trace,
	})

	conf, err := config.DevController(config.WithIPv6Enabled(true))
	require.NoError(err)

	pl, err := net.Listen("tcp", "[::1]:")
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
	require.NotEmpty(t, proxy.ListenerAddr())
	t.Cleanup(func() { _ = proxy.Close() })

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
	tgt, err = tcl.Update(ctx, tgt.Item.Id, tgt.Item.Version, targets.WithTcpTargetDefaultPort(ts.Port()), targets.WithSessionConnectionLimit(-1))
	require.NoError(err)
	require.NotNil(tgt)

	// Authorize a session, connect and send/recv some traffic
	workerInfo := []*targets.WorkerInfo{
		{
			Address: w1.ProxyAddrs()[0],
		},
	}
	sess := helper.NewTestSession(ctx, t, tcl, "ttcp_1234567890", helper.WithWorkerInfo(workerInfo))
	conn := sess.Connect(ctx, t)
	conn.TestSendRecvAll(t)

	// Wait for next statistics update and then check DB for bytes up and down
	w1.Worker().TestWaitForNextSuccessfulStatisticsUpdate(t)

	dbConns1, err := c1.ConnectionsRepo().ListConnectionsBySessionId(ctx, sess.SessionId)
	require.NoError(err)
	require.Len(dbConns1, 1)
	require.NotZero(dbConns1[0].BytesUp)
	require.NotZero(dbConns1[0].BytesDown)

	// Also check the connection data via the API
	sc := sessions.NewClient(c1.Client())
	apiRes1, err := sc.Read(ctx, sess.SessionId)
	require.NoError(err)
	require.Len(apiRes1.Item.Connections, 1)
	require.NotZero(apiRes1.Item.Connections[0].BytesUp)
	require.NotZero(apiRes1.Item.Connections[0].BytesDown)

	// Send/recv some more traffic, close connection, wait for the next statistics
	// update and check everything again.
	conn.TestSendRecvAll(t)
	require.NoError(conn.Close())
	w1.Worker().TestWaitForNextSuccessfulStatisticsUpdate(t)

	dbConns2, err := c1.ConnectionsRepo().ListConnectionsBySessionId(ctx, sess.SessionId)
	require.NoError(err)
	require.Len(dbConns2, 1)
	require.Greater(dbConns2[0].BytesUp, dbConns1[0].BytesUp)
	require.Greater(dbConns2[0].BytesDown, dbConns1[0].BytesDown)
	require.NotEmpty(dbConns2[0].ClosedReason)

	apiRes2, err := sc.Read(ctx, sess.SessionId)
	require.NoError(err)
	require.Len(apiRes2.Item.Connections, 1)
	require.Greater(apiRes2.Item.Connections[0].BytesUp, apiRes1.Item.Connections[0].BytesUp)
	require.Greater(apiRes2.Item.Connections[0].BytesDown, apiRes1.Item.Connections[0].BytesDown)
	require.NotEmpty(apiRes2.Item.Connections[0].ClosedReason)
}
