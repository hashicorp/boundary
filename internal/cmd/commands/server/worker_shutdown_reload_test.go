// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

//go:build !hsm
// +build !hsm

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/api/targets"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/targets/tcp"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/tests/helper"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/testing/controller"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/require"
	"go.uber.org/atomic"
)

const shutdownReloadWorkerProvidedConfiguration = `
disable_mlock = true

worker {
	name = "w_1234567890"
	description = "A default worker created in dev mode"
	initial_upstreams = ["%s"]
}

kms "aead" {
	purpose = "worker-auth"
	aead_type = "aes-gcm"
	key = "%s"
	key_id = "global_worker-auth"
}

listener "tcp" {
	purpose = "proxy"
	address = "127.0.0.1:9205"
}
`

func TestServer_ShutdownWorker(t *testing.T) {
	require := require.New(t)

	rootWrapper, _ := wrapperWithKey(t)
	recoveryWrapper, _ := wrapperWithKey(t)
	workerAuthWrapper, key := wrapperWithKey(t)
	testController := controller.NewTestController(t, controller.WithWorkerAuthKms(workerAuthWrapper), controller.WithRootKms(rootWrapper), controller.WithRecoveryKms(recoveryWrapper))
	t.Cleanup(testController.Shutdown)

	// Start the worker
	workerCmd := testServerCommand(t, testServerCommandOpts{})
	workerCmd.presetConfig = atomic.NewString(fmt.Sprintf(shutdownReloadWorkerProvidedConfiguration, testController.ClusterAddrs()[0], key))

	workerCodeChan := make(chan int)
	go func() {
		workerCodeChan <- workerCmd.Run(nil)
	}()
	waitCh(t, workerCmd.startedCh)

	// Give the worker time for initial status or we can fail because no worker
	// is ready for the connection yet
	time.Sleep(5 * time.Second)

	// Set up the target
	ctx := context.Background()
	client := buildClient(t, testController.ApiAddrs()[0])
	setAuthToken(ctx, t, client)

	tcl := targets.NewClient(client)
	tgtL, err := tcl.List(ctx, scope.Global.String(), targets.WithRecursive(true))
	require.NoError(err)
	require.LessOrEqual(2, len(tgtL.Items))
	tgt := tgtL.Items[0]
	require.NotNil(tgt)
	require.NotNil(tgtL.GetItems()[1])

	// Create test server, update default port on target
	ts := helper.NewTestTcpServer(t)
	require.NotNil(ts)
	t.Cleanup(ts.Close)
	tgtR, err := tcl.Update(ctx, tgt.Id, tgt.Version, targets.WithTcpTargetDefaultPort(ts.Port()))
	require.NoError(err)
	require.NotNil(tgtR)

	// Authorize and connect
	// This prevents us from running tests in parallel.
	server.TestUseCommunityFilterWorkersFn(t)
	sess := helper.NewTestSession(ctx, t, tcl, tgt.Id, helper.WithSkipSessionTeardown(true))
	sConn := sess.Connect(ctx, t)

	// Run initial send/receive test, make sure things are working
	t.Log("running initial send/recv test")
	sConn.TestSendRecvAll(t)

	// Shutdown the worker and close the connection, as the worker will otherwise wait for it to close.
	err = sConn.Close()
	require.NoError(err)

	workerCmd.ShutdownCh <- struct{}{}
	if <-workerCodeChan != 0 {
		output := workerCmd.UI.(*cli.MockUi).ErrorWriter.String() + workerCmd.UI.(*cli.MockUi).OutputWriter.String()
		require.FailNow(output, "command exited with non-zero error code")
	}
	// Connection should fail, and the session should be closed on the DB.
	sConn.TestSendRecvFail(t)
	sess.ExpectConnectionStateOnController(ctx, t, testController.Controller().ConnectionRepoFn, session.StatusClosed)
}

// largely copied from controller/testing.go
func buildClient(t *testing.T, addr string) *api.Client {
	require := require.New(t)
	client, err := api.NewClient(nil)
	require.NoError(err)
	err = client.SetAddr(addr)
	require.NoError(err)
	// Because this is using the real lib it can pick up from stored locations
	// like the system keychain. Explicitly clear the token to ensure we
	// understand the client state at the start of each test.
	client.SetToken("")

	return client
}

func setAuthToken(ctx context.Context, t *testing.T, client *api.Client) {
	require := require.New(t)
	result, err := authmethods.NewClient(client).Authenticate(
		ctx,
		"ampw_1234567890",
		"login",
		map[string]any{
			"login_name": "admin",
			"password":   "passpass",
		},
	)
	require.NoError(err)
	token := new(authtokens.AuthToken)
	err = json.Unmarshal(result.GetRawAttributes(), token)
	require.NoError(err)

	client.SetToken(token.Token)
}

func waitCh(t *testing.T, c chan struct{}) {
	require := require.New(t)
	select {
	case <-c:
	case <-time.After(15 * time.Second):
		require.FailNow("timeout")
	}
}
