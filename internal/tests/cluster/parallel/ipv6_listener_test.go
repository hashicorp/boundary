// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package parallel

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/daemon/worker"
	"github.com/hashicorp/boundary/internal/tests/helper"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

func TestIPv6Listener(t *testing.T) {
	t.Parallel()

	require := require.New(t)
	logger := hclog.New(&hclog.LoggerOptions{
		Level: hclog.Trace,
	})

	conf, err := config.DevController(config.WithIPv6Enabled(true))
	require.NoError(err)

	c1 := controller.NewTestController(t, &controller.TestControllerOpts{
		Config: conf,
		Logger: logger.Named("c1"),
	})

	c2 := c1.AddClusterControllerMember(t, &controller.TestControllerOpts{
		Config: conf,
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

	wconf, err := config.DevWorker(config.WithIPv6Enabled(true))
	require.NoError(err)

	w1 := worker.NewTestWorker(t, &worker.TestWorkerOpts{
		Config:            wconf,
		WorkerAuthKms:     c1.Config().WorkerAuthKms,
		InitialUpstreams:  append(c1.ClusterAddrs(), c2.ClusterAddrs()...),
		Logger:            logger.Named("w1"),
		WorkerRPCInterval: 500 * time.Millisecond,
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

	require.NoError(w1.Worker().Shutdown())

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

	client, err := api.NewClient(nil)
	require.NoError(err)

	addrs := c1.ApiAddrs()
	require.Len(addrs, 1)

	require.NoError(client.SetAddr(addrs[0]))

	sc := scopes.NewClient(client)
	_, err = sc.List(context.Background(), "global")
	require.NoError(err)
}
