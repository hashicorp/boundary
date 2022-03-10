package cluster

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/servers/controller"
	"github.com/hashicorp/boundary/internal/servers/worker"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIPv6Listener(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	logger := hclog.New(&hclog.LoggerOptions{
		Level: hclog.Trace,
	})

	conf, err := config.DevController()
	require.NoError(err)

	for _, l := range conf.Listeners {
		switch l.Purpose[0] {
		case "api":
			l.Address = "[::1]:9200"

		case "cluster":
			l.Address = "[::1]:9201"
		}
	}

	c1 := controller.NewTestController(t, &controller.TestControllerOpts{
		Config: conf,
		Logger: logger.Named("c1"),
	})
	defer c1.Shutdown()

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
			assert.WithinDuration(time.Now(), v.(time.Time), 60*time.Second)
			delete(workerMap, k.(string))
			return true
		})
		assert.Empty(workerMap)
	}

	expectWorkers(c1)

	wconf, err := config.DevWorker()
	require.NoError(err)

	w1 := worker.NewTestWorker(t, &worker.TestWorkerOpts{
		Config:             wconf,
		WorkerAuthKms:      c1.Config().WorkerAuthKms,
		InitialControllers: c1.ClusterAddrs(),
		Logger:             logger.Named("w1"),
	})
	defer w1.Shutdown()

	time.Sleep(10 * time.Second)
	expectWorkers(c1, w1)

	c2 := c1.AddClusterControllerMember(t, &controller.TestControllerOpts{
		Logger: c1.Config().Logger.ResetNamed("c2"),
	})
	defer c2.Shutdown()

	time.Sleep(10 * time.Second)
	expectWorkers(c2, w1)

	require.NoError(w1.Worker().Shutdown(true))
	time.Sleep(10 * time.Second)
	expectWorkers(c1)
	expectWorkers(c2)

	client, err := api.NewClient(nil)
	require.NoError(err)

	addrs := c1.ApiAddrs()
	require.Len(addrs, 1)

	require.NoError(client.SetAddr(addrs[0]))

	sc := scopes.NewClient(client)
	_, err = sc.List(context.Background(), "global")
	require.NoError(err)
}
