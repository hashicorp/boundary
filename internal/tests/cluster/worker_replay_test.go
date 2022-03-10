package cluster

import (
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/servers/controller"
	"github.com/hashicorp/boundary/internal/servers/worker"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

func TestWorkerReplay(t *testing.T) {
	ec := event.TestEventerConfig(t, "TestWorkerReplay", event.TestWithObservationSink(t), event.TestWithSysSink(t))
	testLock := &sync.Mutex{}
	testLogger := hclog.New(&hclog.LoggerOptions{
		Mutex: testLock,
		Name:  "test",
	})
	require.NoError(t, event.InitSysEventer(testLogger, testLock, "use-TestWorkerReplay", event.WithEventerConfig(&ec.EventerConfig)))

	conf, err := config.DevController()
	conf.Eventing = &ec.EventerConfig
	require.NoError(t, err)
	c1 := controller.NewTestController(t, &controller.TestControllerOpts{
		Config: conf,
	})
	defer c1.Shutdown()

	conf, err = config.DevWorker()
	conf.Eventing = &ec.EventerConfig
	require.NoError(t, err)
	w1 := worker.NewTestWorker(t, &worker.TestWorkerOpts{
		Config:             conf,
		WorkerAuthKms:      c1.Config().WorkerAuthKms,
		InitialControllers: c1.ClusterAddrs(),
		NonceFn: func(length int) (string, error) {
			return "test_noncetest_nonce", nil
		},
	})

	// Give time for it to connect
	time.Sleep(10 * time.Second)

	// Assert that the worker has connected
	logBuf, err := os.ReadFile(ec.AllEvents.Name())
	require.NoError(t, err)
	require.Equal(t, 1, strings.Count(string(logBuf), "worker successfully authed"))

	// Assert we have the expected nonce in the DB
	nonces, err := c1.ServersRepo().ListNonces(c1.Context(), servers.NoncePurposeWorkerAuth)
	require.NoError(t, err)
	require.Len(t, nonces, 1)
	require.Equal(t, &servers.Nonce{Nonce: "test_noncetest_nonce", Purpose: servers.NoncePurposeWorkerAuth}, nonces[0])

	require.NoError(t, w1.Worker().Shutdown())

	// Now, start up again with the same nonce
	w1 = worker.NewTestWorker(t, &worker.TestWorkerOpts{
		Config:             conf,
		WorkerAuthKms:      c1.Config().WorkerAuthKms,
		InitialControllers: c1.ClusterAddrs(),
		NonceFn: func(length int) (string, error) {
			return "test_noncetest_nonce", nil
		},
	})

	// Give time for it to connect
	time.Sleep(10 * time.Second)

	// We should find only one nonce, and one successful worker authentication,
	// both in the output and in the database
	ec.AllEvents.Close()
	logBuf, err = os.ReadFile(ec.AllEvents.Name())
	require.NoError(t, err)
	require.Equal(t, 1, strings.Count(string(logBuf), "worker successfully authed"))

	nonces, err = c1.ServersRepo().ListNonces(c1.Context(), servers.NoncePurposeWorkerAuth)
	require.NoError(t, err)
	require.Len(t, nonces, 1)
	require.Equal(t, &servers.Nonce{Nonce: "test_noncetest_nonce", Purpose: servers.NoncePurposeWorkerAuth}, nonces[0])
}
