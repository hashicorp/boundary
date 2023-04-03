// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cluster

import (
	"context"
	"os"
	"path"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/daemon/worker"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

func TestUnixListener(t *testing.T) {
	require := require.New(t)
	logger := hclog.New(&hclog.LoggerOptions{
		Level: hclog.Trace,
	})

	conf, err := config.DevController()
	require.NoError(err)

	tempDir, err := os.MkdirTemp("", "boundary-unix-listener-test")
	require.NoError(err)

	defer func() {
		require.NoError(os.RemoveAll(tempDir))
	}()

	for _, l := range conf.Listeners {
		switch l.Purpose[0] {
		case "api":
			l.Address = path.Join(tempDir, "api")
			l.Type = "unix"

		case "cluster":
			l.Address = path.Join(tempDir, "cluster")
			l.Type = "unix"
		}
	}

	c1 := controller.NewTestController(t, &controller.TestControllerOpts{
		Config:                        conf,
		Logger:                        logger.Named("c1"),
		DisableOidcAuthMethodCreation: true,
	})
	defer c1.Shutdown()

	expectWorkers(t, c1)

	wconf, err := config.DevWorker()
	require.NoError(err)

	w1 := worker.NewTestWorker(t, &worker.TestWorkerOpts{
		Config:           wconf,
		WorkerAuthKms:    c1.Config().WorkerAuthKms,
		InitialUpstreams: c1.ClusterAddrs(),
		Logger:           logger.Named("w1"),
	})
	defer w1.Shutdown()

	time.Sleep(10 * time.Second)
	expectWorkers(t, c1, w1)

	require.NoError(w1.Worker().Shutdown())
	time.Sleep(10 * time.Second)
	expectWorkers(t, c1)

	require.NoError(c1.Controller().Shutdown())
	c1 = controller.NewTestController(t, &controller.TestControllerOpts{
		Config:                        conf,
		Logger:                        logger.Named("c1"),
		DisableOidcAuthMethodCreation: true,
	})
	defer c1.Shutdown()

	time.Sleep(10 * time.Second)
	expectWorkers(t, c1)

	client, err := api.NewClient(nil)
	require.NoError(err)

	addrs := c1.ApiAddrs()
	require.Len(addrs, 1)

	require.NoError(client.SetAddr(addrs[0]))

	sc := scopes.NewClient(client)
	_, err = sc.List(context.Background(), "global")
	require.NoError(err)
}
