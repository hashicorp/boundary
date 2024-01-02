// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package proxy

import (
	"testing"

	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/daemon/worker"
	"github.com/hashicorp/boundary/internal/tests/cluster"
	"github.com/hashicorp/boundary/internal/tests/helper"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

func TestConnectionsLeft(t *testing.T) {
	require := require.New(t)
	logger := hclog.New(&hclog.LoggerOptions{
		Name:  t.Name(),
		Level: hclog.Trace,
	})

	conf, err := config.DevController()
	require.NoError(err)
	c1 := controller.NewTestController(t, &controller.TestControllerOpts{
		Config:                          conf,
		InitialResourcesSuffix:          "1234567890",
		Logger:                          logger.Named("c1"),
		WorkerStatusGracePeriodDuration: helper.DefaultWorkerStatusGracePeriod,
	})
	defer c1.Shutdown()
	cluster.ExpectWorkers(t, c1)

	w1 := worker.NewTestWorker(t, &worker.TestWorkerOpts{
		WorkerAuthKms:                       c1.Config().WorkerAuthKms,
		InitialUpstreams:                    c1.ClusterAddrs(),
		Logger:                              logger.Named("w1"),
		SuccessfulStatusGracePeriodDuration: helper.DefaultWorkerStatusGracePeriod,
	})
	defer w1.Shutdown()
	err = w1.Worker().WaitForNextSuccessfulStatusUpdate()
	require.NoError(err)
	err = c1.WaitForNextWorkerStatusUpdate(w1.Name())
	require.NoError(err)
	cluster.ExpectWorkers(t, c1, w1)

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
	tgt, err = tcl.Update(c1.Context(), tgt.Item.Id, tgt.Item.Version, targets.WithTcpTargetDefaultPort(ts.Port()), targets.WithSessionConnectionLimit(4))
	require.NoError(err)
	require.NotNil(tgt)

	// Authorize and connect
	sess := helper.NewTestSession(c1.Context(), t, tcl, "ttcp_1234567890")
	sConn := sess.Connect(c1.Context(), t)
	sConn.TestSendRecvAll(t)
}
