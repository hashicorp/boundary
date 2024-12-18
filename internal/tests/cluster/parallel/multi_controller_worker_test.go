// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package parallel

import (
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/daemon/worker"
	"github.com/hashicorp/boundary/internal/tests/helper"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

func TestMultiControllerMultiWorkerConnections(t *testing.T) {
	t.Parallel()
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

	c2 := c1.AddClusterControllerMember(t, &controller.TestControllerOpts{
		Logger: c1.Config().Logger.ResetNamed("c2"),
	})

	wg := new(sync.WaitGroup)
	wg.Add(2)
	go func() {
		defer wg.Done()
		helper.ExpectWorkers(t, c1)
	}()
	go func() {
		defer wg.Done()
		helper.ExpectWorkers(t, c2)
	}()
	wg.Wait()

	w1 := worker.NewTestWorker(t, &worker.TestWorkerOpts{
		WorkerAuthKms:    c1.Config().WorkerAuthKms,
		InitialUpstreams: append(c1.ClusterAddrs(), c2.ClusterAddrs()...),
		Logger:           logger.Named("w1"),
	})

	wg.Add(2)
	go func() {
		defer wg.Done()
		helper.ExpectWorkers(t, c1, w1)
	}()
	go func() {
		defer wg.Done()
		helper.ExpectWorkers(t, c2, w1)
	}()
	wg.Wait()

	w2 := w1.AddClusterWorkerMember(t, &worker.TestWorkerOpts{
		Logger: logger.Named("w2"),
	})

	wg.Add(2)
	go func() {
		defer wg.Done()
		helper.ExpectWorkers(t, c1, w1, w2)
	}()
	go func() {
		defer wg.Done()
		helper.ExpectWorkers(t, c2, w1, w2)
	}()
	wg.Wait()

	require.NoError(w1.Worker().Shutdown())

	wg.Add(2)
	go func() {
		defer wg.Done()
		helper.ExpectWorkers(t, c1, w2)
	}()
	go func() {
		defer wg.Done()
		helper.ExpectWorkers(t, c2, w2)
	}()
	wg.Wait()

	w3 := worker.NewTestWorker(t, &worker.TestWorkerOpts{
		WorkerAuthKms:    c1.Config().WorkerAuthKms,
		InitialUpstreams: c1.ClusterAddrs(),
		Logger:           logger.Named("w1"),
	})

	wg.Add(2)
	go func() {
		defer wg.Done()
		helper.ExpectWorkers(t, c1, w2, w3)
	}()
	go func() {
		defer wg.Done()
		helper.ExpectWorkers(t, c2, w2, w3)
	}()
	wg.Wait()

	require.NoError(c2.Controller().Shutdown())

	helper.ExpectWorkers(t, c1, w2, w3)

	c3 := c1.AddClusterControllerMember(t, &controller.TestControllerOpts{
		Logger: c1.Config().Logger.ResetNamed("c3"),
	})

	wg.Add(2)
	go func() {
		defer wg.Done()
		helper.ExpectWorkers(t, c1, w2, w3)
	}()
	go func() {
		defer wg.Done()
		helper.ExpectWorkers(t, c3, w2, w3)
	}()
	wg.Wait()
}

func TestWorkerAppendInitialUpstreams(t *testing.T) {
	t.Parallel()
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
	t.Cleanup(c1.Shutdown)

	helper.ExpectWorkers(t, c1)

	initialUpstreams := append(c1.ClusterAddrs(), "127.0.0.9")
	w1 := worker.NewTestWorker(t, &worker.TestWorkerOpts{
		WorkerAuthKms:                       c1.Config().WorkerAuthKms,
		InitialUpstreams:                    initialUpstreams,
		Logger:                              logger.Named("w1"),
		SuccessfulStatusGracePeriodDuration: 1 * time.Second,
	})
	t.Cleanup(w1.Shutdown)

	// Wait for worker to send status
	helper.ExpectWorkers(t, c1, w1)

	// Upstreams should be equivalent to the controller cluster addr after status updates
	require.Eventually(func() bool {
		if w1.Worker().LastStatusSuccess() == nil {
			return false
		}
		return slices.Equal(c1.ClusterAddrs(), w1.Worker().LastStatusSuccess().LastCalculatedUpstreams)
	}, 4*time.Second, 250*time.Millisecond)

	// Bring down the controller
	c1.Shutdown()
	// Upstreams should now match initial upstreams
	require.Eventually(func() bool {
		return slices.Equal(initialUpstreams, w1.Worker().LastStatusSuccess().LastCalculatedUpstreams)
	}, 4*time.Second, 250*time.Millisecond)
}
