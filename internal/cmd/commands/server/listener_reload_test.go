// +build !hsm

// NOTE on the NOTE: This is from Vault, but that doesn't mean it's not valid
// going forward with us.
//
// NOTE: we can't use this with HSM. We can't set testing mode on and it's not
// safe to use env vars since that provides an attack vector in the real world.
package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/require"
)

const reloadConfig = `
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
	tls_cert_file = "%s/bundle.pem"
	tls_key_file = "%s/bundle.pem"
	cors_enabled = true
	cors_allowed_origins = ["*"]
}

listener "tcp" {
	purpose = "cluster"
}

listener "tcp" {
	purpose = "proxy"
}
`

func TestServer_ReloadListener(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	wg := &sync.WaitGroup{}

	wd, _ := os.Getwd()
	wd += "/test-fixtures/reload/"

	td, err := ioutil.TempDir("", "boundary-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(td)

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
	require.NoError(err)

	// Setup initial certs
	inBytes, err := ioutil.ReadFile(wd + "bundle1.pem")
	require.NoError(err)
	require.NoError(ioutil.WriteFile(td+"/bundle.pem", inBytes, 0o777))

	relHcl := fmt.Sprintf(reloadConfig, cmd.DatabaseUrl, controllerKey, workerAuthKey, recoveryKey, td, td)
	require.NoError(ioutil.WriteFile(td+"/reload.hcl", []byte(relHcl), 0o777))

	// Populate CA pool
	inBytes, _ = ioutil.ReadFile(td + "/bundle.pem")
	certPool := x509.NewCertPool()
	require.True(certPool.AppendCertsFromPEM(inBytes))

	wg.Add(1)
	args := []string{"-config", td + "/reload.hcl"}
	go func() {
		defer wg.Done()
		if code := cmd.Run(args); code != 0 {
			output := cmd.UI.(*cli.MockUi).ErrorWriter.String() + cmd.UI.(*cli.MockUi).OutputWriter.String()
			t.Errorf("got a non-zero exit status: %s", output)
		}
	}()

	testCertificateSerial := func(serial string) {
		conn, err := tls.Dial("tcp", "127.0.0.1:9200", &tls.Config{
			RootCAs: certPool,
		})
		require.NoError(err)
		defer conn.Close()

		require.NoError(conn.Handshake())
		ser := conn.ConnectionState().PeerCertificates[0].SerialNumber.String()
		require.Equal(ser, serial)
	}

	select {
	case <-cmd.startedCh:
	case <-time.After(15 * time.Second):
		t.Fatalf("timeout")
	}

	testCertificateSerial("142541707881583626546634262782315760343015820827")

	inBytes, err = ioutil.ReadFile(wd + "bundle2.pem")
	require.NoError(err)
	require.NoError(ioutil.WriteFile(td+"/bundle.pem", inBytes, 0o777))

	cmd.SighupCh <- struct{}{}
	select {
	case <-cmd.reloadedCh:
	case <-time.After(5 * time.Second):
		t.Fatalf("timeout")
	}

	testCertificateSerial("193080739105342897219784862820114567438786419504")

	close(cmd.ShutdownCh)

	wg.Wait()
}
