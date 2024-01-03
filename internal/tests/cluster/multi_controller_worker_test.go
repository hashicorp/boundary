// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cluster

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/daemon/worker"
	"github.com/hashicorp/boundary/internal/tests/helper"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMultiControllerMultiWorkerConnections(t *testing.T) {
	require := require.New(t)
	logger := hclog.New(&hclog.LoggerOptions{
		Level: hclog.Trace,
	})

	conf, err := config.DevController()
	require.NoError(err)

	c1 := controller.NewTestController(t, &controller.TestControllerOpts{
		Config: conf,
		Logger: logger.Named("c1"),
	})
	defer c1.Shutdown()

	c2 := c1.AddClusterControllerMember(t, &controller.TestControllerOpts{
		Logger: c1.Config().Logger.ResetNamed("c2"),
	})
	defer c2.Shutdown()

	helper.ExpectWorkers(t, c1)
	helper.ExpectWorkers(t, c2)

	w1 := worker.NewTestWorker(t, &worker.TestWorkerOpts{
		WorkerAuthKms:    c1.Config().WorkerAuthKms,
		InitialUpstreams: c1.ClusterAddrs(),
		Logger:           logger.Named("w1"),
	})
	defer w1.Shutdown()

	time.Sleep(10 * time.Second)
	helper.ExpectWorkers(t, c1, w1)
	helper.ExpectWorkers(t, c2, w1)

	w2 := w1.AddClusterWorkerMember(t, &worker.TestWorkerOpts{
		Logger: logger.Named("w2"),
	})
	defer w2.Shutdown()

	time.Sleep(10 * time.Second)
	helper.ExpectWorkers(t, c1, w1, w2)
	helper.ExpectWorkers(t, c2, w1, w2)

	require.NoError(w1.Worker().Shutdown())
	time.Sleep(10 * time.Second)
	helper.ExpectWorkers(t, c1, w2)
	helper.ExpectWorkers(t, c2, w2)

	w1 = worker.NewTestWorker(t, &worker.TestWorkerOpts{
		WorkerAuthKms:    c1.Config().WorkerAuthKms,
		InitialUpstreams: c1.ClusterAddrs(),
		Logger:           logger.Named("w1"),
	})
	defer w1.Shutdown()

	time.Sleep(10 * time.Second)
	helper.ExpectWorkers(t, c1, w1, w2)
	helper.ExpectWorkers(t, c2, w1, w2)

	require.NoError(c2.Controller().Shutdown())
	time.Sleep(10 * time.Second)
	helper.ExpectWorkers(t, c1, w1, w2)

	c2 = c1.AddClusterControllerMember(t, &controller.TestControllerOpts{
		Logger: c1.Config().Logger.ResetNamed("c2"),
	})
	defer c2.Shutdown()

	time.Sleep(10 * time.Second)
	helper.ExpectWorkers(t, c1, w1, w2)
	helper.ExpectWorkers(t, c2, w1, w2)
}

func TestWorkerAppendInitialUpstreams(t *testing.T) {
	ctx := context.Background()
	require, assert := require.New(t), assert.New(t)
	logger := hclog.New(&hclog.LoggerOptions{
		Level: hclog.Trace,
	})

	conf, err := config.DevController()
	require.NoError(err)

	c1 := controller.NewTestController(t, &controller.TestControllerOpts{
		Config: conf,
		Logger: logger.Named("c1"),
	})
	defer c1.Shutdown()

	helper.ExpectWorkers(t, c1)

	initialUpstreams := append(c1.ClusterAddrs(), "127.0.0.9")
	w1 := worker.NewTestWorker(t, &worker.TestWorkerOpts{
		WorkerAuthKms:                       c1.Config().WorkerAuthKms,
		InitialUpstreams:                    initialUpstreams,
		Logger:                              logger.Named("w1"),
		SuccessfulStatusGracePeriodDuration: 1 * time.Second,
	})
	defer w1.Shutdown()

	// Wait for worker to send status
	cancelCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	t.Cleanup(cancel)
	for {
		select {
		case <-time.After(500 * time.Millisecond):
		case <-cancelCtx.Done():
			require.FailNow("No worker found after 10 seconds")
		}
		successSent := w1.Worker().LastStatusSuccess()
		if successSent != nil {
			break
		}
	}
	helper.ExpectWorkers(t, c1, w1)

	// Upstreams should be equivalent to the controller cluster addr after status updates
	assert.Equal(c1.ClusterAddrs(), w1.Worker().LastStatusSuccess().LastCalculatedUpstreams)

	// Bring down the controller
	c1.Shutdown()
	time.Sleep(3 * time.Second) // Wait a little longer than the grace period

	// Upstreams should now match initial upstreams
	assert.True(strutil.EquivalentSlices(initialUpstreams, w1.Worker().LastStatusSuccess().LastCalculatedUpstreams))
}
