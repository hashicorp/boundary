package controller_test

import (
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/watchtower/internal/servers/controller"
	"github.com/hashicorp/watchtower/internal/servers/worker"
)

func TestMultiControllerWorker(t *testing.T) {
	//assert, require := assert.New(t), require.New(t)
	amId := "paum_1234567890"
	user := "jeff"
	password := "passpass"
	orgId := "o_1234567890"
	logger := hclog.New(&hclog.LoggerOptions{
		Level: hclog.Trace,
	})

	c1 := controller.NewTestController(t, &controller.TestControllerOpts{
		DefaultOrgId:        orgId,
		DefaultAuthMethodId: amId,
		DefaultUsername:     user,
		DefaultPassword:     password,
		Logger:              logger.Named("c1"),
	})
	defer c1.Shutdown()

	c2 := c1.AddClusterControllerMember(t, &controller.TestControllerOpts{
		Logger: c1.Config().Logger.ResetNamed("c2"),
	})
	defer c2.Shutdown()

	w1 := worker.NewTestWorker(t, &worker.TestWorkerOpts{
		WorkerAuthKMS:      c1.Config().WorkerAuthKMS,
		InitialControllers: c1.ClusterAddrs(),
		Logger:             logger.Named("w1"),
	})
	defer w1.Shutdown()

	w2 := w1.AddClusterWorkerMember(t, &worker.TestWorkerOpts{
		Logger: logger.Named("w2"),
	})
	defer w2.Shutdown()

	time.Sleep(10 * time.Second)
}
