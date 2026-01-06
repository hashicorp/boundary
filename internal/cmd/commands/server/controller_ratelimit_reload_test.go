// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"fmt"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	ratelimitConfig = `
disable_mlock = true

telemetry {
	prometheus_retention_time = "24h"
	disable_hostname = true
}

controller {
	name = "test-controller"
	description = "A default controller created for tests"
	database {
		url = "%s"
	}

	api_rate_limit {
		resources = ["*"]
		actions   = ["*"]
		per       = "total"
		limit     = 2
		period    = "1m"
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
	address = "127.0.0.1:9500"
	tls_disable = true
}

listener "tcp" {
	address = "127.0.0.1:9501"
	purpose = "cluster"
}
`

	ratelimitConfigReload = `
disable_mlock = true

telemetry {
	prometheus_retention_time = "24h"
	disable_hostname = true
}

controller {
	name = "test-controller"
	description = "A default controller created for tests"
	database {
		url = "%s"
	}

	api_rate_limit {
		resources = ["*"]
		actions   = ["*"]
		per       = "total"
		limit     = 5
		period    = "1m"
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
	address = "127.0.0.1:9500"
	tls_disable = true
}

listener "tcp" {
	address = "127.0.0.1:9501"
	purpose = "cluster"
}
`

	ratelimitConfigDisabledReload = `
disable_mlock = true

telemetry {
	prometheus_retention_time = "24h"
	disable_hostname = true
}

controller {
	name = "test-controller"
	description = "A default controller created for tests"
	database {
		url = "%s"
	}

	api_rate_limit_disable = true
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
	address = "127.0.0.1:9500"
	tls_disable = true
}

listener "tcp" {
	address = "127.0.0.1:9501"
	purpose = "cluster"
}  
`
)

func TestReloadControllerRateLimits(t *testing.T) {
	td := t.TempDir()

	controllerKey := config.DevKeyGeneration()

	closeDB, url, _, err := getInitDatabase(t, controllerKey)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, closeDB()) })

	cmd := testServerCommand(t, testServerCommandOpts{})

	workerAuthKey := config.DevKeyGeneration()
	recoveryKey := config.DevKeyGeneration()
	cfgHcl := fmt.Sprintf(ratelimitConfig, url, controllerKey, workerAuthKey, recoveryKey)
	require.NoError(t, os.WriteFile(td+"/config.hcl", []byte(cfgHcl), 0o644))

	wg := &sync.WaitGroup{}
	wg.Add(1)
	earlyExitChan := make(chan struct{})
	go func() {
		defer wg.Done()
		args := []string{"-config", td + "/config.hcl"}
		exitCode := cmd.Run(args)
		if exitCode != 0 {
			output := cmd.UI.(*cli.MockUi).ErrorWriter.String() + cmd.UI.(*cli.MockUi).OutputWriter.String()
			fmt.Printf("%s: got a non-zero exit status: %s", t.Name(), output)
		}
		select {
		case earlyExitChan <- struct{}{}:
		default:
		}
	}()

	// Wait until things are up and running (or timeout).
	select {
	case <-cmd.startedCh:
	case <-earlyExitChan:
		t.Fatal("server exited early")
	case <-time.After(30 * time.Second):
		t.Fatal("timeout waiting for server to start")
	}

	// Change config so it is ready for reloading
	cfgHcl = fmt.Sprintf(ratelimitConfigReload, url, controllerKey, workerAuthKey, recoveryKey)
	require.NoError(t, os.WriteFile(td+"/config.hcl", []byte(cfgHcl), 0o644))

	c := http.Client{}
	r, err := c.Do(func() *http.Request {
		r, err := http.NewRequest(http.MethodGet, `http://127.0.0.1:9500/v1/targets`, nil)
		require.NoError(t, err)
		return r
	}())
	require.NoError(t, err)
	// unauthed request, so we expect a 400
	assert.Equal(t, http.StatusBadRequest, r.StatusCode)
	assert.Equal(t, `limit=2, remaining=1, reset=60`, r.Header.Get("Ratelimit"))
	assert.Equal(t, `2;w=60;comment="total", 1500;w=30;comment="ip-address", 150;w=30;comment="auth-token"`, r.Header.Get("Ratelimit-Policy"))

	r, err = c.Do(func() *http.Request {
		r, err := http.NewRequest(http.MethodGet, `http://127.0.0.1:9500/v1/targets`, nil)
		require.NoError(t, err)
		return r
	}())
	require.NoError(t, err)
	// unauthed request, so we expect a 400
	assert.Equal(t, http.StatusBadRequest, r.StatusCode)
	assert.Equal(t, `limit=2, remaining=0, reset=60`, r.Header.Get("Ratelimit"))
	assert.Equal(t, `2;w=60;comment="total", 1500;w=30;comment="ip-address", 150;w=30;comment="auth-token"`, r.Header.Get("Ratelimit-Policy"))

	r, err = c.Do(func() *http.Request {
		r, err := http.NewRequest(http.MethodGet, `http://127.0.0.1:9500/v1/targets`, nil)
		require.NoError(t, err)
		return r
	}())
	require.NoError(t, err)
	// out of quota, so we expect a 429
	assert.Equal(t, http.StatusTooManyRequests, r.StatusCode)
	assert.Equal(t, `limit=2, remaining=0, reset=60`, r.Header.Get("Ratelimit"))
	assert.Equal(t, `2;w=60;comment="total", 1500;w=30;comment="ip-address", 150;w=30;comment="auth-token"`, r.Header.Get("Ratelimit-Policy"))

	cmd.SighupCh <- struct{}{}
	select {
	case <-cmd.reloadedCh:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for reload signal")
	}

	// Make another request, the limit should have reset and the new limit
	// should get reported via the headers.
	r, err = c.Do(func() *http.Request {
		r, err := http.NewRequest(http.MethodGet, `http://127.0.0.1:9500/v1/targets`, nil)
		require.NoError(t, err)
		return r
	}())
	require.NoError(t, err)
	// unauthed request, so we expect a 400
	assert.Equal(t, http.StatusBadRequest, r.StatusCode)
	assert.Equal(t, `limit=5, remaining=4, reset=60`, r.Header.Get("Ratelimit"))
	assert.Equal(t, `5;w=60;comment="total", 1500;w=30;comment="ip-address", 150;w=30;comment="auth-token"`, r.Header.Get("Ratelimit-Policy"))

	cmd.ShutdownCh <- struct{}{}
	wg.Wait()
}

func TestReloadControllerRateLimitsSameConfig(t *testing.T) {
	td := t.TempDir()

	// Create and migrate database A and B.
	controllerKey := config.DevKeyGeneration()

	closeDB, url, _, err := getInitDatabase(t, controllerKey)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, closeDB()) })

	cmd := testServerCommand(t, testServerCommandOpts{})

	workerAuthKey := config.DevKeyGeneration()
	recoveryKey := config.DevKeyGeneration()
	cfgHcl := fmt.Sprintf(ratelimitConfig, url, controllerKey, workerAuthKey, recoveryKey)
	require.NoError(t, os.WriteFile(td+"/config.hcl", []byte(cfgHcl), 0o644))

	wg := &sync.WaitGroup{}
	wg.Add(1)
	earlyExitChan := make(chan struct{})
	go func() {
		defer wg.Done()

		args := []string{"-config", td + "/config.hcl"}
		exitCode := cmd.Run(args)
		if exitCode != 0 {
			output := cmd.UI.(*cli.MockUi).ErrorWriter.String() + cmd.UI.(*cli.MockUi).OutputWriter.String()
			fmt.Printf("%s: got a non-zero exit status: %s", t.Name(), output)
		}
		select {
		case earlyExitChan <- struct{}{}:
		default:
		}
	}()

	// Wait until things are up and running (or timeout).
	select {
	case <-cmd.startedCh:
	case <-earlyExitChan:
		t.Fatal("server exited early")
	case <-time.After(30 * time.Second):
		t.Fatal("timeout waiting for server to start")
	}

	c := http.Client{}
	r, err := c.Do(func() *http.Request {
		r, err := http.NewRequest(http.MethodGet, `http://127.0.0.1:9500/v1/targets`, nil)
		require.NoError(t, err)
		return r
	}())
	require.NoError(t, err)
	// unauthed request, so we expect a 400
	assert.Equal(t, http.StatusBadRequest, r.StatusCode)
	assert.Equal(t, `limit=2, remaining=1, reset=60`, r.Header.Get("Ratelimit"))
	assert.Equal(t, `2;w=60;comment="total", 1500;w=30;comment="ip-address", 150;w=30;comment="auth-token"`, r.Header.Get("Ratelimit-Policy"))

	r, err = c.Do(func() *http.Request {
		r, err := http.NewRequest(http.MethodGet, `http://127.0.0.1:9500/v1/targets`, nil)
		require.NoError(t, err)
		return r
	}())
	require.NoError(t, err)
	// unauthed request, so we expect a 400
	assert.Equal(t, http.StatusBadRequest, r.StatusCode)
	assert.Equal(t, `limit=2, remaining=0, reset=60`, r.Header.Get("Ratelimit"))
	assert.Equal(t, `2;w=60;comment="total", 1500;w=30;comment="ip-address", 150;w=30;comment="auth-token"`, r.Header.Get("Ratelimit-Policy"))

	r, err = c.Do(func() *http.Request {
		r, err := http.NewRequest(http.MethodGet, `http://127.0.0.1:9500/v1/targets`, nil)
		require.NoError(t, err)
		return r
	}())
	require.NoError(t, err)
	// out of quota, so we expect a 429
	assert.Equal(t, http.StatusTooManyRequests, r.StatusCode)
	assert.Equal(t, `limit=2, remaining=0, reset=60`, r.Header.Get("Ratelimit"))
	assert.Equal(t, `2;w=60;comment="total", 1500;w=30;comment="ip-address", 150;w=30;comment="auth-token"`, r.Header.Get("Ratelimit-Policy"))

	cmd.SighupCh <- struct{}{}
	select {
	case <-cmd.reloadedCh:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout")
	}

	// Make another request, the limit should not have reset, and the current
	// quota should still apply.
	r, err = c.Do(func() *http.Request {
		r, err := http.NewRequest(http.MethodGet, `http://127.0.0.1:9500/v1/targets`, nil)
		require.NoError(t, err)
		return r
	}())
	require.NoError(t, err)
	// should still be rate limited, so 429
	assert.Equal(t, http.StatusTooManyRequests, r.StatusCode)
	assert.Equal(t, `limit=2, remaining=0, reset=60`, r.Header.Get("Ratelimit"))
	assert.Equal(t, `2;w=60;comment="total", 1500;w=30;comment="ip-address", 150;w=30;comment="auth-token"`, r.Header.Get("Ratelimit-Policy"))

	cmd.ShutdownCh <- struct{}{}
	wg.Wait()
}

func TestReloadControllerRateLimitsDisable(t *testing.T) {
	td := t.TempDir()

	controllerKey := config.DevKeyGeneration()

	closeDB, url, _, err := getInitDatabase(t, controllerKey)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, closeDB()) })

	cmd := testServerCommand(t, testServerCommandOpts{})

	workerAuthKey := config.DevKeyGeneration()
	recoveryKey := config.DevKeyGeneration()
	cfgHcl := fmt.Sprintf(ratelimitConfig, url, controllerKey, workerAuthKey, recoveryKey)
	require.NoError(t, os.WriteFile(td+"/config.hcl", []byte(cfgHcl), 0o644))

	wg := &sync.WaitGroup{}
	wg.Add(1)
	earlyExitChan := make(chan struct{})
	go func() {
		defer wg.Done()

		args := []string{"-config", td + "/config.hcl"}
		exitCode := cmd.Run(args)
		if exitCode != 0 {
			output := cmd.UI.(*cli.MockUi).ErrorWriter.String() + cmd.UI.(*cli.MockUi).OutputWriter.String()
			fmt.Printf("%s: got a non-zero exit status: %s", t.Name(), output)
		}
		select {
		case earlyExitChan <- struct{}{}:
		default:
		}
	}()

	// Wait until things are up and running (or timeout).
	select {
	case <-cmd.startedCh:
	case <-earlyExitChan:
		t.Fatal("server exited early")
	case <-time.After(30 * time.Second):
		t.Fatal("timeout waiting for server to start")
	}

	// Change config so it is ready for reloading
	cfgHcl = fmt.Sprintf(ratelimitConfigDisabledReload, url, controllerKey, workerAuthKey, recoveryKey)
	require.NoError(t, os.WriteFile(td+"/config.hcl", []byte(cfgHcl), 0o644))

	c := http.Client{}
	r, err := c.Do(func() *http.Request {
		r, err := http.NewRequest(http.MethodGet, `http://127.0.0.1:9500/v1/targets`, nil)
		require.NoError(t, err)
		return r
	}())
	require.NoError(t, err)
	// unauthed request, so we expect a 400
	assert.Equal(t, http.StatusBadRequest, r.StatusCode)
	assert.Equal(t, `limit=2, remaining=1, reset=60`, r.Header.Get("Ratelimit"))
	assert.Equal(t, `2;w=60;comment="total", 1500;w=30;comment="ip-address", 150;w=30;comment="auth-token"`, r.Header.Get("Ratelimit-Policy"))

	r, err = c.Do(func() *http.Request {
		r, err := http.NewRequest(http.MethodGet, `http://127.0.0.1:9500/v1/targets`, nil)
		require.NoError(t, err)
		return r
	}())
	require.NoError(t, err)
	// unauthed request, so we expect a 400
	assert.Equal(t, http.StatusBadRequest, r.StatusCode)
	assert.Equal(t, `limit=2, remaining=0, reset=60`, r.Header.Get("Ratelimit"))
	assert.Equal(t, `2;w=60;comment="total", 1500;w=30;comment="ip-address", 150;w=30;comment="auth-token"`, r.Header.Get("Ratelimit-Policy"))

	r, err = c.Do(func() *http.Request {
		r, err := http.NewRequest(http.MethodGet, `http://127.0.0.1:9500/v1/targets`, nil)
		require.NoError(t, err)
		return r
	}())
	require.NoError(t, err)
	// out of quota, so we expect a 429
	assert.Equal(t, http.StatusTooManyRequests, r.StatusCode)
	assert.Equal(t, `limit=2, remaining=0, reset=60`, r.Header.Get("Ratelimit"))
	assert.Equal(t, `2;w=60;comment="total", 1500;w=30;comment="ip-address", 150;w=30;comment="auth-token"`, r.Header.Get("Ratelimit-Policy"))

	cmd.SighupCh <- struct{}{}
	select {
	case <-cmd.reloadedCh:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout")
	}

	// Make another request, the limit should be disabled
	// should get reported via the headers.
	r, err = c.Do(func() *http.Request {
		r, err := http.NewRequest(http.MethodGet, `http://127.0.0.1:9500/v1/targets`, nil)
		require.NoError(t, err)
		return r
	}())
	require.NoError(t, err)
	// unauthed request, so we expect a 400
	assert.Equal(t, http.StatusBadRequest, r.StatusCode)
	assert.Equal(t, ``, r.Header.Get("Ratelimit"))
	assert.Equal(t, ``, r.Header.Get("Ratelimit-Policy"))

	cmd.ShutdownCh <- struct{}{}
	wg.Wait()
}

func TestReloadControllerRateLimitsEnable(t *testing.T) {
	td := t.TempDir()

	controllerKey := config.DevKeyGeneration()

	closeDB, url, _, err := getInitDatabase(t, controllerKey)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, closeDB()) })

	cmd := testServerCommand(t, testServerCommandOpts{})

	workerAuthKey := config.DevKeyGeneration()
	recoveryKey := config.DevKeyGeneration()
	// Start with rate limiting diasabled
	cfgHcl := fmt.Sprintf(ratelimitConfigDisabledReload, url, controllerKey, workerAuthKey, recoveryKey)
	require.NoError(t, os.WriteFile(td+"/config.hcl", []byte(cfgHcl), 0o644))

	wg := &sync.WaitGroup{}
	wg.Add(1)
	earlyExitChan := make(chan struct{})
	go func() {
		defer wg.Done()

		args := []string{"-config", td + "/config.hcl"}
		exitCode := cmd.Run(args)
		if exitCode != 0 {
			output := cmd.UI.(*cli.MockUi).ErrorWriter.String() + cmd.UI.(*cli.MockUi).OutputWriter.String()
			fmt.Printf("%s: got a non-zero exit status: %s", t.Name(), output)
		}
		select {
		case earlyExitChan <- struct{}{}:
		default:
		}
	}()

	// Wait until things are up and running (or timeout).
	select {
	case <-cmd.startedCh:
	case <-earlyExitChan:
		t.Fatal("server exited early")
	case <-time.After(30 * time.Second):
		t.Fatal("timeout waiting for server to start")
	}

	// Change config so it is ready for reloading
	cfgHcl = fmt.Sprintf(ratelimitConfig, url, controllerKey, workerAuthKey, recoveryKey)
	require.NoError(t, os.WriteFile(td+"/config.hcl", []byte(cfgHcl), 0o644))

	c := http.Client{}
	r, err := c.Do(func() *http.Request {
		r, err := http.NewRequest(http.MethodGet, `http://127.0.0.1:9500/v1/targets`, nil)
		require.NoError(t, err)
		return r
	}())
	require.NoError(t, err)
	// unauthed request, so we expect a 400
	assert.Equal(t, http.StatusBadRequest, r.StatusCode)
	assert.Equal(t, ``, r.Header.Get("Ratelimit"))
	assert.Equal(t, ``, r.Header.Get("Ratelimit-Policy"))

	cmd.SighupCh <- struct{}{}
	select {
	case <-cmd.reloadedCh:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout")
	}

	// Make another request, the limit should be enabled
	// should get reported via the headers.
	r, err = c.Do(func() *http.Request {
		r, err := http.NewRequest(http.MethodGet, `http://127.0.0.1:9500/v1/targets`, nil)
		require.NoError(t, err)
		return r
	}())
	require.NoError(t, err)
	// unauthed request, so we expect a 400
	assert.Equal(t, http.StatusBadRequest, r.StatusCode)
	assert.Equal(t, `limit=2, remaining=1, reset=60`, r.Header.Get("Ratelimit"))
	assert.Equal(t, `2;w=60;comment="total", 1500;w=30;comment="ip-address", 150;w=30;comment="auth-token"`, r.Header.Get("Ratelimit-Policy"))

	r, err = c.Do(func() *http.Request {
		r, err := http.NewRequest(http.MethodGet, `http://127.0.0.1:9500/v1/targets`, nil)
		require.NoError(t, err)
		return r
	}())
	require.NoError(t, err)
	// unauthed request, so we expect a 400
	assert.Equal(t, http.StatusBadRequest, r.StatusCode)
	assert.Equal(t, `limit=2, remaining=0, reset=60`, r.Header.Get("Ratelimit"))
	assert.Equal(t, `2;w=60;comment="total", 1500;w=30;comment="ip-address", 150;w=30;comment="auth-token"`, r.Header.Get("Ratelimit-Policy"))

	r, err = c.Do(func() *http.Request {
		r, err := http.NewRequest(http.MethodGet, `http://127.0.0.1:9500/v1/targets`, nil)
		require.NoError(t, err)
		return r
	}())
	require.NoError(t, err)
	// out of quota, so we expect a 429
	assert.Equal(t, http.StatusTooManyRequests, r.StatusCode)
	assert.Equal(t, `limit=2, remaining=0, reset=60`, r.Header.Get("Ratelimit"))
	assert.Equal(t, `2;w=60;comment="total", 1500;w=30;comment="ip-address", 150;w=30;comment="auth-token"`, r.Header.Get("Ratelimit-Policy"))

	cmd.ShutdownCh <- struct{}{}
	wg.Wait()
}
