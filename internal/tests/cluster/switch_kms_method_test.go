// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cluster

import (
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/daemon/worker"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWorkerUpgradeKmsAuthMethod(t *testing.T) {
	ec := event.TestEventerConfig(t, "TestWorkerUpgradeKmsAuthMethod", event.TestWithObservationSink(t), event.TestWithSysSink(t))
	testLock := &sync.Mutex{}
	testLogger := hclog.New(&hclog.LoggerOptions{
		Mutex: testLock,
		Name:  "test",
	})
	require.NoError(t, event.InitSysEventer(testLogger, testLock, "use-TestWorkerUpgradeKmsAuthMethod", event.WithEventerConfig(&ec.EventerConfig)))

	conf, err := config.DevController()
	conf.Eventing = &ec.EventerConfig
	require.NoError(t, err)
	c1 := controller.NewTestController(t, &controller.TestControllerOpts{
		Config: conf,
	})
	defer c1.Shutdown()
	serversRepo := c1.ServersRepo()

	conf, err = config.DevWorker()
	conf.Eventing = &ec.EventerConfig
	require.NoError(t, err)
	w1 := worker.NewTestWorker(t, &worker.TestWorkerOpts{
		Config:                     conf,
		WorkerAuthKms:              c1.Config().WorkerAuthKms,
		InitialUpstreams:           c1.ClusterAddrs(),
		UseDeprecatedKmsAuthMethod: true,
	})
	defer w1.Shutdown()

	// Give time for it to connect
	time.Sleep(10 * time.Second)

	// Verify it's KMS type
	workers, err := serversRepo.ListWorkers(c1.Context(), []string{scope.Global.String()})
	require.NoError(t, err)
	require.Len(t, workers, 1)
	assert.Equal(t, "kms", workers[0].Type)
	oldId := workers[0].PublicId

	// Assert that the worker has connected
	logBuf, err := os.ReadFile(ec.AllEvents.Name())
	require.NoError(t, err)
	require.Equal(t, 1, strings.Count(string(logBuf), "worker successfully authed"))

	require.NoError(t, w1.Worker().Shutdown())

	// Now, start up again, using the new method
	w1 = worker.NewTestWorker(t, &worker.TestWorkerOpts{
		Config:           conf,
		WorkerAuthKms:    c1.Config().WorkerAuthKms,
		InitialUpstreams: c1.ClusterAddrs(),
	})
	defer w1.Shutdown()

	// Give time for it to connect
	time.Sleep(10 * time.Second)

	// We should find only one nonce, and one successful worker authentication,
	// both in the output and in the database
	ec.AllEvents.Close()
	logBuf, err = os.ReadFile(ec.AllEvents.Name())
	require.NoError(t, err)
	require.Equal(t, 2, strings.Count(string(logBuf), "worker has successfully authenticated"))

	// Verify it's PKI type
	workers, err = serversRepo.ListWorkers(c1.Context(), []string{scope.Global.String()})
	require.NoError(t, err)
	require.Len(t, workers, 1)
	assert.Equal(t, "pki", workers[0].Type)
	assert.Equal(t, oldId, workers[0].PublicId)
}
