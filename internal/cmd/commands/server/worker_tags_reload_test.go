// +build !hsm

// NOTE on the NOTE: This is from Vault, but that doesn't mean it's not valid
// going forward with us.
//
// NOTE: we can't use this with HSM. We can't set testing mode on and it's not
// safe to use env vars since that provides an attack vector in the real world.

package server

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/require"
	"go.uber.org/atomic"
)

const workerBaseConfig = `
disable_mlock = true

telemetry {
	prometheus_retention_time = "24h"
	disable_hostname = true
}

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

kms "aead" {
	purpose = "recovery"
	aead_type = "aes-gcm"
	key = "%s"
	key_id = "global_recovery"
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

listener "tcp" {
	purpose = "proxy"
	address = "127.0.0.1:9205"
}

`

const tag1Config = `
worker {
	name = "dev-worker"
	description = "A default worker created in dev mode"
	controllers = ["127.0.0.1:9204"]
	tags {
		type = ["dev", "local"]
	}
}
`

const tag2Config = `
worker {
	name = "dev-worker"
	description = "A default worker created in dev mode"
	controllers = ["127.0.0.1:9204"]
	tags {
		foo = ["bar", "baz"]
	}
}
`

func TestServer_ReloadWorkerTags(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	wg := &sync.WaitGroup{}

	controllerKey, workerAuthKey, recoveryKey := config.DevKeyGeneration()

	cmd := testServerCommand(t, testServerCommandOpts{
		CreateDevDatabase: true,
		ControllerKey:     controllerKey,
		UseDevAuthMethod:  true,
		UseDevTarget:      true,
	})
	defer func() {
		if cmd.DevDatabaseCleanupFunc != nil {
			require.NoError(cmd.DevDatabaseCleanupFunc())
		}
	}()

	cmd.presetConfig = atomic.NewString(fmt.Sprintf(workerBaseConfig+tag1Config, cmd.DatabaseUrl, controllerKey, workerAuthKey, recoveryKey))

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
		t.Fatalf("timeout")
	}

	fetchWorkerTags := func(name string, key string, values []string) {
		t.Helper()
		serversRepo, err := cmd.controller.ServersRepoFn()
		require.NoError(err)
		tags, err := serversRepo.ListTagsForServers(cmd.Context, []string{name})
		require.NoError(err)
		require.Len(tags, 2)
		require.Equal(key, tags[0].Key)
		require.Equal(values[0], tags[0].Value)
		require.Equal(key, tags[1].Key)
		require.Equal(values[1], tags[1].Value)
	}

	// Give time to populate up to the controller
	time.Sleep(10 * time.Second)
	fetchWorkerTags("dev-worker", "type", []string{"dev", "local"})

	cmd.presetConfig.Store(fmt.Sprintf(workerBaseConfig+tag2Config, cmd.DatabaseUrl, controllerKey, workerAuthKey, recoveryKey))

	cmd.SighupCh <- struct{}{}
	select {
	case <-cmd.reloadedCh:
	case <-time.After(15 * time.Second):
		t.Fatalf("timeout")
	}

	time.Sleep(10 * time.Second)
	fetchWorkerTags("dev-worker", "foo", []string{"bar", "baz"})

	close(cmd.ShutdownCh)

	wg.Wait()
}
