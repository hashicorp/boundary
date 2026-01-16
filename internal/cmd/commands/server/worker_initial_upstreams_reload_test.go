// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

//go:build !hsm

package server

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/server"
	tc "github.com/hashicorp/boundary/testing/controller"
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
	require := require.New(t)

	rootWrapper, _ := wrapperWithKey(t)
	recoveryWrapper, _ := wrapperWithKey(t)
	workerAuthWrapper, key := wrapperWithKey(t)

	testController := tc.NewTestController(
		t,
		tc.WithWorkerAuthKms(workerAuthWrapper),
		tc.WithRootKms(rootWrapper),
		tc.WithRecoveryKms(recoveryWrapper),
		tc.DisableDatabaseDestruction(),
	)
	t.Cleanup(testController.Shutdown)

	testController2 := testController.AddClusterControllerMember(t, &controller.TestControllerOpts{
		DisableAutoStart: true,
	})

	wg := &sync.WaitGroup{}

	cmd := testServerCommand(t, testServerCommandOpts{})
	cmd.presetConfig = atomic.NewString(fmt.Sprintf(initialUpstreamConfig, key, testController.ClusterAddrs()[0]))

	wg.Add(1)
	go func() {
		defer wg.Done()
		if code := cmd.Run(nil); code != 0 {
			output := cmd.UI.(*cli.MockUi).ErrorWriter.String() + cmd.UI.(*cli.MockUi).OutputWriter.String()
			fmt.Printf("%s: got a non-zero exit status: %s", t.Name(), output)
		}
	}()

	select {
	case <-cmd.startedCh:
	case <-time.After(15 * time.Second):
		t.Fatalf("timeout waiting for worker start")
	}

	// Wait until the worker has connected to the first controller as seen via
	// two status updates
	timeout := time.NewTimer(15 * time.Second)
	poll := time.NewTimer(0)
	var w *server.Worker
	var lastStatusTime time.Time
	serversRepo, err := testController.Controller().ServersRepoFn()
	require.NoError(err)
pollFirstController:
	for {
		select {
		case <-timeout.C:
			t.Fatalf("timeout wait for worker to connect to first controller")
		case <-poll.C:
			w, err = server.TestLookupWorkerByName(testController.Context(), t, "test", serversRepo)
			require.NoError(err)
			if w != nil {
				switch {
				case lastStatusTime.IsZero():
					lastStatusTime = w.GetLastStatusTime().AsTime().Round(time.Second)
				default:
					if !lastStatusTime.Equal(w.GetLastStatusTime().AsTime().Round(time.Second)) {
						timeout.Stop()
						break pollFirstController
					}
				}
			}
			poll.Reset(time.Second)
		}
	}

	// Shut down first controller, start second, then ensure we are no longer
	// seeing status updates.
	testController.Shutdown()
	require.NoError(testController2.Controller().Start())
	t.Cleanup(testController2.Shutdown)

	lastStatusTime = time.Time{}
	timeout.Reset(15 * time.Second)
	poll.Reset(0)
	serversRepo, err = testController2.Controller().ServersRepoFn()
	require.NoError(err)
pollForNoStatus:
	for {
		select {
		case <-timeout.C:
			// Great, didn't see it
			poll.Stop()
			break pollForNoStatus
		case <-poll.C:
			w, err = server.TestLookupWorkerByName(testController2.Context(), t, "test", serversRepo)
			require.NoError(err)
			if w != nil {
				switch {
				case lastStatusTime.IsZero():
					lastStatusTime = w.GetLastStatusTime().AsTime().Round(time.Second)
				default:
					if !lastStatusTime.Equal(w.GetLastStatusTime().AsTime().Round(time.Second)) {
						t.Fatal("found updated status times when not expected")
					}
				}
			}
			poll.Reset(time.Second)
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
	poll.Reset(time.Second)
	lastStatusTime = time.Time{}
pollSecondController:
	for {
		select {
		case <-timeout.C:
			t.Fatalf("timeout wait for worker to connect to second controller")
		case <-poll.C:
			w, err = server.TestLookupWorkerByName(testController2.Context(), t, "test", serversRepo)
			require.NoError(err)
			if w != nil {
				switch {
				case lastStatusTime.IsZero():
					lastStatusTime = w.GetLastStatusTime().AsTime().Round(time.Second)
				default:
					if !lastStatusTime.Round(time.Second).Equal(w.GetLastStatusTime().AsTime().Round(time.Second)) {
						timeout.Stop()
						break pollSecondController
					}
				}
			}
			poll.Reset(time.Second)
		}
	}
	cmd.ShutdownCh <- struct{}{}
	wg.Wait()
}
