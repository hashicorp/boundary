//go:build !hsm
// +build !hsm

// NOTE on the NOTE: This is from Vault, but that doesn't mean it's not valid
// going forward with us.
//
// NOTE: we can't use this with HSM. We can't set testing mode on and it's not
// safe to use env vars since that provides an attack vector in the real world.

package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/testing/controller"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/require"
	"go.uber.org/atomic"
)

const workerBaseConfig = `
disable_mlock = true

kms "aead" {
	purpose = "worker-auth"
	aead_type = "aes-gcm"
	key = "%s"
	key_id = "global_worker-auth"
}

listener "tcp" {
	purpose = "proxy"
	address = "127.0.0.1:9405"
}
`

const tag1Config = `
worker {
	name = "w_1234567890"
	description = "A default worker created in dev mode"
	controllers = ["%s"]
	tags {
		type = ["dev", "local"]
	}
}
`

const tag2Config = `
worker {
	name = "w_1234567890"
	description = "A default worker created in dev mode"
	controllers = ["%s"]
	tags {
		foo = ["bar", "baz"]
	}
}
`

func TestServer_ReloadWorkerTags(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	rootWrapper, _ := wrapperWithKey(t)
	recoveryWrapper, _ := wrapperWithKey(t)
	workerAuthWrapper, key := wrapperWithKey(t)
	testController := controller.NewTestController(t, controller.WithWorkerAuthKms(workerAuthWrapper), controller.WithRootKms(rootWrapper), controller.WithRecoveryKms(recoveryWrapper))
	defer testController.Shutdown()

	wg := &sync.WaitGroup{}

	cmd := testServerCommand(t, testServerCommandOpts{})
	cmd.presetConfig = atomic.NewString(fmt.Sprintf(workerBaseConfig+tag1Config, key, testController.ClusterAddrs()[0]))

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
		serversRepo, err := testController.Controller().ServersRepoFn()
		require.NoError(err)
		tags, err := serversRepo.ListTagsForWorkers(testController.Context(), []string{name})
		require.NoError(err)
		require.Len(tags, 2)
		require.Equal(key, tags[0].Key)
		require.Equal(values[0], tags[0].Value)
		require.Equal(key, tags[1].Key)
		require.Equal(values[1], tags[1].Value)
	}

	// Give time to populate up to the controller
	time.Sleep(10 * time.Second)
	fetchWorkerTags("w_1234567890", "type", []string{"dev", "local"})

	cmd.presetConfig.Store(fmt.Sprintf(workerBaseConfig+tag2Config, key, testController.ClusterAddrs()[0]))

	cmd.SighupCh <- struct{}{}
	select {
	case <-cmd.reloadedCh:
	case <-time.After(15 * time.Second):
		t.Fatalf("timeout")
	}

	time.Sleep(10 * time.Second)
	fetchWorkerTags("w_1234567890", "foo", []string{"bar", "baz"})

	close(cmd.ShutdownCh)

	wg.Wait()
}

// TestWrapper initializes an AEAD wrapping.Wrapper for testing the oplog
func wrapperWithKey(t testing.TB) (wrapping.Wrapper, string) {
	t.Helper()
	rootKey := make([]byte, 32)
	n, err := rand.Read(rootKey)
	if err != nil {
		t.Fatal(err)
	}
	if n != 32 {
		t.Fatal(n)
	}
	root := aead.NewWrapper()
	_, err = root.SetConfig(context.Background(), wrapping.WithKeyId(base64.StdEncoding.EncodeToString(rootKey)))
	if err != nil {
		t.Fatal(err)
	}
	if err := root.SetAesGcmKeyBytes(rootKey); err != nil {
		t.Fatal(err)
	}
	return root, base64.StdEncoding.EncodeToString(rootKey)
}
