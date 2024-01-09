// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package worker

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/connectivity"
)

func TestDeleteConnectedWorkers(t *testing.T) {
	ctx := context.Background()
	logger := hclog.New(&hclog.LoggerOptions{
		Level: hclog.Trace,
	})
	conf, err := config.DevController()
	require.NoError(t, err)
	c := controller.NewTestController(t, &controller.TestControllerOpts{
		Config: conf,
		Logger: logger.Named("controller"),
	})
	_, directPkiWorker, multiHoppedPkiWorker, multiHoppedKmsWorker := NewTestMultihopWorkers(t, logger, c.Context(), c.ClusterAddrs(),
		c.Config().WorkerAuthKms, c.Controller().ServersRepoFn, nil, nil, nil, nil)

	serverRepo, err := c.Controller().ServersRepoFn()
	require.NoError(t, err)
	workerTimeoutCtx, workerTimeoutCancel := context.WithTimeout(ctx, 5*time.Minute)
	defer workerTimeoutCancel()
	var pkiWorker, childPkiWorker, childKmsWorker *server.Worker
	for pkiWorker == nil || childPkiWorker == nil || childKmsWorker == nil {
		time.Sleep(time.Second)
		select {
		case <-workerTimeoutCtx.Done():
			require.FailNow(t, "timeout waiting for all workers to connect")
		default:
			workers, err := serverRepo.ListWorkers(workerTimeoutCtx, []string{"global"}, server.WithLiveness(-1))
			require.NoError(t, err)
			for _, w := range workers {
				if w.Type == "pki" && w.GetAddress() == multiHoppedPkiWorker.ProxyAddrs()[0] {
					childPkiWorker = w
				}
				if w.Type == "pki" && w.GetAddress() == multiHoppedKmsWorker.ProxyAddrs()[0] {
					childKmsWorker = w
				}
				if w.Type == "pki" && w.GetAddress() == directPkiWorker.ProxyAddrs()[0] {
					pkiWorker = w
				}
			}
		}
	}

	cases := []struct {
		name       string
		workerId   string
		testWorker *TestWorker
	}{
		{
			name:       "multi hop pki worker",
			workerId:   childPkiWorker.GetPublicId(),
			testWorker: multiHoppedPkiWorker,
		},
		{
			name:       "multi hop kms worker",
			workerId:   childKmsWorker.GetPublicId(),
			testWorker: multiHoppedKmsWorker,
		},
		{
			name:       "directly connected worker",
			workerId:   pkiWorker.GetPublicId(),
			testWorker: directPkiWorker,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prevState := tc.testWorker.Worker().GrpcClientConn.GetState()
			require.NotEqual(t, connectivity.TransientFailure, prevState)
			require.NotEqual(t, connectivity.Shutdown, prevState)
			_, err = serverRepo.DeleteWorker(ctx, tc.workerId)
			require.NoError(t, err)
			stateChangeCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
			defer cancel()
			for {
				tc.testWorker.Worker().GrpcClientConn.ResetConnectBackoff()
				if !tc.testWorker.Worker().GrpcClientConn.WaitForStateChange(stateChangeCtx, prevState) {
					assert.Fail(t, "State didn't change before context timed out")
					break
				}
				newState := tc.testWorker.Worker().GrpcClientConn.GetState()
				t.Logf("Changed from previous state: %s to new state: %s", prevState, newState)
				if newState == connectivity.Shutdown || newState == connectivity.TransientFailure {
					break
				}
				prevState = newState
			}
		})
	}
}
