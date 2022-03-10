package cluster

import (
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/servers/controller"
	"github.com/hashicorp/boundary/internal/servers/worker"
	"github.com/hashicorp/go-hclog"
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

	expectWorkers(t, c1)
	expectWorkers(t, c2)

	w1 := worker.NewTestWorker(t, &worker.TestWorkerOpts{
		WorkerAuthKms:      c1.Config().WorkerAuthKms,
		InitialControllers: c1.ClusterAddrs(),
		Logger:             logger.Named("w1"),
	})
	defer w1.Shutdown()

	time.Sleep(10 * time.Second)
	expectWorkers(t, c1, w1)
	expectWorkers(t, c2, w1)

	w2 := w1.AddClusterWorkerMember(t, &worker.TestWorkerOpts{
		Logger: logger.Named("w2"),
	})
	defer w2.Shutdown()

	time.Sleep(10 * time.Second)
	expectWorkers(t, c1, w1, w2)
	expectWorkers(t, c2, w1, w2)

	require.NoError(w1.Worker().Shutdown(true))
	time.Sleep(10 * time.Second)
	expectWorkers(t, c1, w2)
	expectWorkers(t, c2, w2)

	require.NoError(w1.Worker().Start())
	time.Sleep(10 * time.Second)
	expectWorkers(t, c1, w1, w2)
	expectWorkers(t, c2, w1, w2)

	require.NoError(c2.Controller().Shutdown())
	time.Sleep(10 * time.Second)
	expectWorkers(t, c2, w1, w2)

	require.NoError(c1.Controller().Start())
	time.Sleep(10 * time.Second)
	expectWorkers(t, c1, w1, w2)
	expectWorkers(t, c2, w1, w2)
}
