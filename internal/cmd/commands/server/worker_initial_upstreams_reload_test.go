// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


//go:build !hsm

package server

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/testing/controller"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/require"
	"go.uber.org/atomic"
)

const initialUpstreamConfig = `
disable_mlock = true

kms "aead" {
	purpose = "worker-auth"
	aead_type = "aes-gcm"
	key = "%s"
	key_id = "global_worker-auth"
}

listener "tcp" {
	purpose = "proxy"
	address = "127.0.0.1:9406"
}

worker {
	name = "test"
	description = "A default worker created in dev mode"
	initial_upstreams = ["%s"]
	tags {
		type = ["dev", "local"]
	}
}
`

func TestServer_ReloadInitialUpstreams(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	rootWrapper, _ := wrapperWithKey(t)
	recoveryWrapper, _ := wrapperWithKey(t)
	workerAuthWrapper, key := wrapperWithKey(t)

	// Create two controllers, each with their own database. In practice it
	// would be odd to have separate databases, but it makes it easy for the
	// test to assert that the worker has connected to the second controller
	// after a reload signal is sent.
	testController := controller.NewTestController(
		t,
		controller.WithWorkerAuthKms(workerAuthWrapper),
		controller.WithRootKms(rootWrapper),
		controller.WithRecoveryKms(recoveryWrapper),
	)
	defer testController.Shutdown()
	testController2 := controller.NewTestController(
		t,
		controller.WithWorkerAuthKms(workerAuthWrapper),
		controller.WithRootKms(rootWrapper),
		controller.WithRecoveryKms(recoveryWrapper),
	)
	defer testController2.Shutdown()
	require.NotEqual(testController.Config().DatabaseUrl, testController2.Config().DatabaseUrl)

	wg := &sync.WaitGroup{}

	cmd := testServerCommand(t, testServerCommandOpts{})
	cmd.presetConfig = atomic.NewString(fmt.Sprintf(initialUpstreamConfig, key, testController.ClusterAddrs()[0]))

	wg.Add(1)
	go func() {
		defer wg.Done()
		if code := cmd.Run(nil); code != 0 {
			output := cmd.UI.(*cli.MockUi).ErrorWriter.String() + cmd.UI.(*cli.MockUi).OutputWriter.String()
			t.Errorf("got a non-zero exit status: %s", output)
		}
	}()

	select {
	case <-cmd.startedCh:
	case <-time.After(15 * time.Second):
		t.Fatalf("timeout waiting for worker start")
	}

	// Wait until the worker has connected to the first controller
	timeout := time.NewTimer(15 * time.Second)
	poll := time.NewTimer(0)
	var w *server.Worker
pollFirstController:
	for {
		select {
		case <-timeout.C:
			t.Fatalf("timeout wait for worker to connect to first controller")
		case <-poll.C:
			serversRepo, err := testController.Controller().ServersRepoFn()
			require.NoError(err)
			w, err = serversRepo.LookupWorkerByName(testController.Context(), "test")
			require.NoError(err)
			if w != nil {
				timeout.Stop()
				break pollFirstController
			}
			poll.Reset(1 * time.Millisecond)
		}
	}

	// Reload the config after changing initial_upstreams to the second controller
	cmd.presetConfig.Store(fmt.Sprintf(initialUpstreamConfig, key, testController2.ClusterAddrs()[0]))
	cmd.SighupCh <- struct{}{}
	select {
	case <-cmd.reloadedCh:
	case <-time.After(15 * time.Second):
		t.Fatalf("timeout waiting for worker reload")
	}

	// Wait until the worker connects to the second controller
	timeout.Reset(15 * time.Second)
	poll.Reset(10 * time.Millisecond)
pollSecondController:
	for {
		select {
		case <-timeout.C:
			t.Fatalf("timeout wait for worker to connect to second controller")
		case <-poll.C:
			serversRepo, err := testController2.Controller().ServersRepoFn()
			require.NoError(err)
			w, err = serversRepo.LookupWorkerByName(testController2.Context(), "test")
			require.NoError(err)
			if w != nil {
				break pollSecondController
			}
			poll.Reset(1 * time.Millisecond)
		}
	}

	cmd.ShutdownCh <- struct{}{}
	wg.Wait()
}
