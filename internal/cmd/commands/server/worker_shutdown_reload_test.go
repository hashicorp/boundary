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
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/tests/helper"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/require"
	"go.uber.org/atomic"

	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/targets/tcp"
)

const shutdownReloadApiAddr = "http://127.0.0.1:9203"

const shutdownReloadControllerConfig = `
disable_mlock = true

controller {
	name = "dev-controller"
	description = "A default controller created in dev mode"
	database {
		url = "%s"
	}
}

kms "aead" {
	purpose = "root"
	aead_type = "aes-gcm"
	key = "%s"
	key_id = "global_root"
}

kms "aead" {
	purpose = "worker-auth"
	aead_type = "aes-gcm"
	key = "%s"
	key_id = "global_worker-auth"
}

listener "tcp" {
	purpose = "api"
	address = "127.0.0.1:9203"
	tls_disable = true
	cors_enabled = true
	cors_allowed_origins = ["*"]
}

listener "tcp" {
	purpose = "cluster"
	address = "127.0.0.1:9204"
}
`

const shutdownReloadWorkerConfig = `
disable_mlock = true

worker {
	name = "w_1234567890"
	description = "A default worker created in dev mode"
	controllers = ["127.0.0.1:9204"]
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
	controllerKey, workerAuthKey, _ := config.DevKeyGeneration()

	// Start the controller
	controllerCmd := testServerCommand(t, testServerCommandOpts{
		CreateDevDatabase: true,
		ControllerKey:     controllerKey,
		UseDevAuthMethod:  true,
		UseDevTarget:      true,
	})
	t.Cleanup(func() {
		if controllerCmd.DevDatabaseCleanupFunc != nil {
			require.NoError(controllerCmd.DevDatabaseCleanupFunc())
		}
	})
	controllerCmd.presetConfig = atomic.NewString(fmt.Sprintf(shutdownReloadControllerConfig, controllerCmd.DatabaseUrl, controllerKey, workerAuthKey))

	// Use code channel so that we can use test assertions on the returned integer.
	// It is illegal to call `t.FailNow()` from a goroutine.
	// https://pkg.go.dev/testing#T.FailNow
	controllerCodeChan := make(chan int)
	go func() {
		controllerCodeChan <- controllerCmd.Run(nil)
	}()

	waitCh(t, controllerCmd.startedCh)

	// Start the worker
	workerCmd := testServerCommand(t, testServerCommandOpts{})
	workerCmd.presetConfig = atomic.NewString(fmt.Sprintf(shutdownReloadWorkerConfig, workerAuthKey))

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
	client := buildClient(t, shutdownReloadApiAddr)
	setAuthToken(ctx, t, client)

	tcl := targets.NewClient(client)
	tgt, err := tcl.Read(ctx, "ttcp_1234567890")
	require.NoError(err)
	require.NotNil(tgt)

	// Create test server, update default port on target
	ts := helper.NewTestTcpServer(t)
	require.NotNil(ts)
	defer ts.Close()
	tgt, err = tcl.Update(ctx, tgt.Item.Id, tgt.Item.Version, targets.WithTcpTargetDefaultPort(ts.Port()))
	require.NoError(err)
	require.NotNil(tgt)

	// Authorize and connect
	sess := helper.NewTestSession(ctx, t, tcl, "ttcp_1234567890")
	sConn := sess.Connect(ctx, t)

	// Run initial send/receive test, make sure things are working
	t.Log("running initial send/recv test")
	sConn.TestSendRecvAll(t)

	// Now, shut the worker down.
	close(workerCmd.ShutdownCh)
	if <-workerCodeChan != 0 {
		output := workerCmd.UI.(*cli.MockUi).ErrorWriter.String() + workerCmd.UI.(*cli.MockUi).OutputWriter.String()
		require.FailNow(output, "command exited with non-zero error code")
	}

	// Connection should fail, and the session should be closed on the DB.
	sConn.TestSendRecvFail(t)
	sess.ExpectConnectionStateOnController(ctx, t, controllerCmd.controller.ConnectionRepoFn, session.StatusClosed)

	// We're done! Shutdown the controller, and that's it.
	close(controllerCmd.ShutdownCh)
	if <-controllerCodeChan != 0 {
		output := controllerCmd.UI.(*cli.MockUi).ErrorWriter.String() + controllerCmd.UI.(*cli.MockUi).OutputWriter.String()
		require.FailNow(output, "command exited with non-zero error code")
	}
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
		map[string]interface{}{
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
