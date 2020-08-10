package cluster

import (
	"testing"
	"time"

	"github.com/alecthomas/assert"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/watchtower/internal/servers/controller"
	"github.com/hashicorp/watchtower/internal/servers/worker"
	"github.com/stretchr/testify/require"
)

func TestMultiControllerWorker(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	amId := "paum_1234567890"
	user := "user"
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

	expectWorkers := func(c *controller.TestController, workers ...*worker.TestWorker) {
		updateTimes := c.Controller().WorkerStatusUpdateTimes()
		workerMap := map[string]*worker.TestWorker{}
		for _, w := range workers {
			workerMap[w.Name()] = w
		}
		updateTimes.Range(func(k, v interface{}) bool {
			require.NotNil(k)
			require.NotNil(v)
			if workerMap[k.(string)] == nil {
				// We don't remove from updateTimes currently so if we're not
				// expecting it we'll see an out-of-date entry
				return true
			}
			assert.WithinDuration(time.Now(), v.(time.Time), 7*time.Second)
			delete(workerMap, k.(string))
			return true
		})
		assert.Empty(workerMap)
	}

	expectWorkers(c1)
	expectWorkers(c2)

	w1 := worker.NewTestWorker(t, &worker.TestWorkerOpts{
		WorkerAuthKMS:      c1.Config().WorkerAuthKMS,
		InitialControllers: c1.ClusterAddrs(),
		Logger:             logger.Named("w1"),
	})
	defer w1.Shutdown()

	time.Sleep(10 * time.Second)
	expectWorkers(c1, w1)
	expectWorkers(c2, w1)

	w2 := w1.AddClusterWorkerMember(t, &worker.TestWorkerOpts{
		Logger: logger.Named("w2"),
	})
	defer w2.Shutdown()

	time.Sleep(10 * time.Second)
	expectWorkers(c1, w1, w2)
	expectWorkers(c2, w1, w2)

	require.NoError(w1.Worker().Shutdown(true))
	time.Sleep(10 * time.Second)
	expectWorkers(c1, w2)
	expectWorkers(c2, w2)

	require.NoError(w1.Worker().Start())
	time.Sleep(10 * time.Second)
	expectWorkers(c1, w1, w2)
	expectWorkers(c2, w1, w2)
}
