// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package parallel

import (
	"bytes"
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
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/tests/helper"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

func TestUnixListener(t *testing.T) {
	t.Parallel()

	require := require.New(t)
	buf := new(bytes.Buffer)
	logger := hclog.New(&hclog.LoggerOptions{
		Level: hclog.Trace,
	})

	conf, err := config.DevController()
	require.NoError(err)

	tempDir, err := os.MkdirTemp("", "boundary-unix-listener-test")
	require.NoError(err)

	t.Cleanup(func() {
		require.NoError(os.RemoveAll(tempDir))
	})

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
		EventerConfig: &event.EventerConfig{
			ObservationsEnabled: true,
			SysEventsEnabled:    true,
			Sinks: []*event.SinkConfig{
				{
					Name: "output",
					Type: event.WriterSink,
					EventTypes: []event.Type{
						event.EveryType,
					},
					WriterConfig: &event.WriterSinkTypeConfig{
						Writer: buf,
					},
					Format: event.TextHclogSinkFormat,
				},
			},
		},
	})

	helper.ExpectWorkers(t, c1)

	wconf, err := config.DevWorker()
	require.NoError(err)

	w1 := worker.NewTestWorker(t, &worker.TestWorkerOpts{
		Config:            wconf,
		WorkerAuthKms:     c1.Config().WorkerAuthKms,
		InitialUpstreams:  c1.ClusterAddrs(),
		Logger:            logger.Named("w1"),
		WorkerRPCInterval: 500 * time.Millisecond,
	})

	helper.ExpectWorkers(t, c1, w1)

	require.NoError(w1.Worker().Shutdown())
	helper.ExpectWorkers(t, c1)

	require.NoError(c1.Controller().Shutdown())

	conf, err = config.DevController()
	require.NoError(err)

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

	c2 := controller.NewTestController(t, &controller.TestControllerOpts{
		Config:                        conf,
		Logger:                        logger.Named("c2"),
		DisableOidcAuthMethodCreation: true,
		EventerConfig: &event.EventerConfig{
			ObservationsEnabled: true,
			SysEventsEnabled:    true,
			Sinks: []*event.SinkConfig{
				{
					Name: "output",
					Type: event.WriterSink,
					EventTypes: []event.Type{
						event.EveryType,
					},
					WriterConfig: &event.WriterSinkTypeConfig{
						Writer: buf,
					},
					Format: event.TextHclogSinkFormat,
				},
			},
		},
	})

	helper.ExpectWorkers(t, c2)

	client, err := api.NewClient(nil)
	require.NoError(err)

	addrs := c2.ApiAddrs()
	require.Len(addrs, 1)

	require.NoError(client.SetAddr(addrs[0]))

	sc := scopes.NewClient(client)
	_, err = sc.List(context.Background(), "global")
	require.NoError(err)
}
