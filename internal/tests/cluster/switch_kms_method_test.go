// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cluster

import (
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/daemon/worker"
	"github.com/hashicorp/boundary/internal/event"
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

	require.NoError(t, c1.WaitForNextWorkerStatusUpdate(w1.Name()))

	// Verify it's KMS type
	workers, err := serversRepo.ListWorkersUnpaginated(c1.Context(), []string{scope.Global.String()})
	require.NoError(t, err)
	require.Len(t, workers, 1)
	assert.Equal(t, "kms", workers[0].Type)
	oldId := workers[0].PublicId

	require.NoError(t, w1.Worker().Shutdown())

	// Now, start up again, using the new method
	w1 = worker.NewTestWorker(t, &worker.TestWorkerOpts{
		Config:           conf,
		WorkerAuthKms:    c1.Config().WorkerAuthKms,
		InitialUpstreams: c1.ClusterAddrs(),
	})
	defer w1.Shutdown()

	require.NoError(t, c1.WaitForNextWorkerStatusUpdate(w1.Name()))

	// Verify it's PKI type
	workers, err = serversRepo.ListWorkersUnpaginated(c1.Context(), []string{scope.Global.String()})
	require.NoError(t, err)
	require.Len(t, workers, 1)
	assert.Equal(t, "pki", workers[0].Type)
	assert.Equal(t, oldId, workers[0].PublicId)
}
