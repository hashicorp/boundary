// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cluster

import (
	"context"
	"net"
	"testing"

	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	tg "github.com/hashicorp/boundary/internal/daemon/controller/handlers/targets"
	"github.com/hashicorp/boundary/internal/daemon/worker"
	"github.com/hashicorp/boundary/internal/tests/helper"
	"github.com/hashicorp/dawdle"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

func TestWorkerBytesUpDown(t *testing.T) {
	require := require.New(t)

	// This prevents us from running tests in parallel.
	tg.SetupSuiteTargetFilters(t)

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
		WorkerAuthKms:                       c1.Config().WorkerAuthKms,
		InitialUpstreams:                    []string{proxy.ListenerAddr()},
		Logger:                              logger.Named("w1"),
		SuccessfulStatusGracePeriodDuration: helper.DefaultSuccessfulStatusGracePeriod,
	})

	require.NoError(w1.Worker().WaitForNextSuccessfulStatusUpdate())
	require.NoError(c1.WaitForNextWorkerStatusUpdate(w1.Name()))
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
	sess := helper.NewTestSession(ctx, t, tcl, "ttcp_1234567890")
	conn := sess.Connect(ctx, t)
	conn.TestSendRecvAll(t)

	// Wait for next status and then check DB for bytes up and down
	require.NoError(w1.Worker().WaitForNextSuccessfulStatusUpdate())
	require.NoError(c1.WaitForNextWorkerStatusUpdate(w1.Name()))

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

	// Send/recv some more traffic, close connection, wait for the next status
	// update and check everything again.
	conn.TestSendRecvAll(t)
	require.NoError(conn.Close())
	require.NoError(w1.Worker().WaitForNextSuccessfulStatusUpdate())
	require.NoError(c1.WaitForNextWorkerStatusUpdate(w1.Name()))

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
