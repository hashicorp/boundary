// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

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
	name = "test"
	description = "A default worker created in dev mode"
	initial_upstreams = ["%s"]
	tags {
		type = ["dev", "local"]
	}
}
`

const tag2Config = `
worker {
	name = "test"
	description = "A default worker created in dev mode"
	initial_upstreams = ["%s"]
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
		w, err := serversRepo.LookupWorkerByName(testController.Context(), name)
		require.NoError(err)
		require.NotNil(w)
		v, ok := w.CanonicalTags()[key]
		require.True(ok)
		require.ElementsMatch(values, v)
	}

	// Give time to populate up to the controller
	time.Sleep(10 * time.Second)
	fetchWorkerTags("test", "type", []string{"dev", "local"})

	cmd.presetConfig.Store(fmt.Sprintf(workerBaseConfig+tag2Config, key, testController.ClusterAddrs()[0]))

	cmd.SighupCh <- struct{}{}
	select {
	case <-cmd.reloadedCh:
	case <-time.After(15 * time.Second):
		t.Fatalf("timeout")
	}

	time.Sleep(10 * time.Second)
	fetchWorkerTags("test", "foo", []string{"bar", "baz"})

	cmd.ShutdownCh <- struct{}{}

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
