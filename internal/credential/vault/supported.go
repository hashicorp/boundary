// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build linux || darwin || windows
// +build linux darwin windows

package vault

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/go-rootcerts"
	"github.com/hashicorp/go-secure-stdlib/base62"
	vault "github.com/hashicorp/vault/api"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/require"
)

const DefaultVaultVersion = "1.15.1"

var (
	vaultRepository    = "hashicorp/vault"
	postgresRepository = "postgres"
)

func init() {
	newVaultServer = gotNewServer
	mountDatabase = gotMountDatabase

	mirror := os.Getenv("DOCKER_MIRROR")
	if mirror != "" {
		vaultRepository = strings.Join([]string{mirror, vaultRepository}, "/")
		postgresRepository = strings.Join([]string{mirror, postgresRepository}, "/")
	}
}

func gotDocker(t testing.TB) {}

func gotNewServer(t testing.TB, opt ...TestOption) *TestVaultServer {
	const (
		serverTlsTemplate = `{
  "listener": [
    {
      "tcp": {
        "address": "0.0.0.0:8200",
        "tls_disable": "false",
        "tls_cert_file": "/vault/config/certificates/certificate.pem",
        "tls_key_file": "/vault/config/certificates/key.pem"
      }
    }
  ]
}
`

		clientTlsTemplate = `{
  "listener": [
    {
      "tcp": {
        "address": "0.0.0.0:8200",
        "tls_disable": "false",
        "tls_cert_file": "/vault/config/certificates/certificate.pem",
        "tls_key_file": "/vault/config/certificates/key.pem",
		"tls_require_and_verify_client_cert": "true",
		"tls_client_ca_file": "/vault/config/certificates/client-ca-certificate.pem"
      }
    }
  ]
}
`
	)

	require := require.New(t)
	pool, err := dockertest.NewPool("")
	require.NoError(err)
	opts := getTestOpts(t, opt...)

	server := &TestVaultServer{
		RootToken: fmt.Sprintf("icu-root-%s", t.Name()),
		pool:      pool,
	}

	vaultVersion := DefaultVaultVersion
	if opts.vaultVersion != "" {
		vaultVersion = opts.vaultVersion
	}

	dockerOptions := &dockertest.RunOptions{
		Repository: vaultRepository,
		Tag:        vaultVersion,
		Env:        []string{fmt.Sprintf("VAULT_DEV_ROOT_TOKEN_ID=%s", server.RootToken)},
	}

	vConfig := vault.DefaultConfig()

	if opts.vaultTLS != TestNoTLS {
		dockerOptions.Env = append(dockerOptions.Env, "VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8300")

		switch opts.vaultTLS {
		case TestServerTLS:
			dockerOptions.Env = append(dockerOptions.Env, fmt.Sprintf("VAULT_LOCAL_CONFIG=%s", serverTlsTemplate))
		case TestClientTLS:
			dockerOptions.Env = append(dockerOptions.Env, fmt.Sprintf("VAULT_LOCAL_CONFIG=%s", clientTlsTemplate))
		}

		serverCert := testServerCert(t, testCaCert(t), opt...)
		server.serverCertBundle = serverCert
		server.ServerCert = serverCert.Cert.Cert
		server.CaCert = serverCert.CA.Cert

		clientTLSConfig := vConfig.HttpClient.Transport.(*http.Transport).TLSClientConfig
		rootConfig := &rootcerts.Config{
			CACertificate: serverCert.CA.Cert,
		}
		require.NoError(rootcerts.ConfigureTLS(clientTLSConfig, rootConfig))

		dataSrcDir := t.TempDir()
		require.NoError(os.Chmod(dataSrcDir, 0o777))
		caCertFn := filepath.Join(dataSrcDir, "ca-certificate.pem")
		require.NoError(os.WriteFile(caCertFn, serverCert.CA.Cert, 0o777))
		certFn := filepath.Join(dataSrcDir, "certificate.pem")
		require.NoError(os.WriteFile(certFn, serverCert.Cert.Cert, 0o777))
		keyFn := filepath.Join(dataSrcDir, "key.pem")
		require.NoError(os.WriteFile(keyFn, serverCert.Cert.Key, 0o777))
		dockerOptions.Mounts = append(dockerOptions.Mounts, fmt.Sprintf("%s:/vault/config/certificates", dataSrcDir))

		if opts.vaultTLS == TestClientTLS {
			clientCert := testClientCert(t, testCaCert(t), opt...)
			server.clientCertBundle = clientCert
			server.ClientCert = clientCert.Cert.Cert
			server.ClientKey = clientCert.Cert.Key
			clientCaCertFn := filepath.Join(dataSrcDir, "client-ca-certificate.pem")
			require.NoError(os.WriteFile(clientCaCertFn, clientCert.CA.Cert, 0o777))

			vaultClientCert, err := tls.X509KeyPair(server.ClientCert, server.ClientKey)
			require.NoError(err)
			clientTLSConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return &vaultClientCert, nil
			}
		}
		server.TlsSkipVerify = true
		clientTLSConfig.InsecureSkipVerify = true
	}

	// NOTE(mgaffney) 05/2021: creating a docker network is not the default
	// because it added a significant amount time to the tests.
	//
	// For reference, running 'go test .'
	// - without creating a docker network by default: 259.668s
	// - with creating a docker network by default: 553.497s
	//
	// Machine: MacBook Pro (15-inch, 2018)
	// Processor: 2.6 GHz 6-Core Intel Core i7
	// Memory: 16 GB 2400 MHz DDR4
	// OS: 10.15.7 (Catalina)
	//
	// Docker
	// Desktop: 3.3.3 (64133)
	// Engine: 20.10.6

	if opts.dockerNetwork {
		id, err := base62.Random(4)
		require.NoError(err)
		network, err := pool.CreateNetwork(fmt.Sprintf("%s-%s", t.Name(), id))
		require.NoError(err)
		server.network = network
		dockerOptions.Networks = []*dockertest.Network{network}
		if !opts.skipCleanup {
			t.Cleanup(func() {
				network.Close()
			})
		}
	}

	resource, err := pool.RunWithOptions(dockerOptions)
	require.NoError(err)
	if !opts.skipCleanup {
		t.Cleanup(func() {
			cleanupResource(t, pool, resource)
		})
	}
	server.vaultContainer = resource

	switch opts.vaultTLS {
	case TestNoTLS:
		server.Addr = fmt.Sprintf("http://localhost:%s", resource.GetPort("8200/tcp"))
	case TestServerTLS, TestClientTLS:
		server.Addr = fmt.Sprintf("https://localhost:%s", resource.GetPort("8200/tcp"))
	default:
		t.Fatal("unknown TLS option")
	}

	vConfig.Address = server.Addr
	client, err := vault.NewClient(vConfig)
	require.NoError(err)
	client.SetToken(server.RootToken)

	err = pool.Retry(func() error {
		if _, err := client.Sys().Health(); err != nil {
			return err
		}
		return nil
	})
	require.NoError(err)

	server.addPolicy(t, "boundary-controller", requiredCapabilities)
	return server
}

func gotMountDatabase(t testing.TB, v *TestVaultServer, opt ...TestOption) *TestDatabase {
	require := require.New(t)
	require.Nil(v.postgresContainer, "postgres container exists")
	require.NotNil(v.network, "Vault server must be created with docker network")

	pool, ok := v.pool.(*dockertest.Pool)
	require.True(ok)
	network, ok := v.network.(*dockertest.Network)
	require.True(ok)

	dockerOptions := &dockertest.RunOptions{
		Repository: postgresRepository,
		Tag:        globals.MinimumSupportedPostgresVersion,
		Networks:   []*dockertest.Network{network},
		Env:        []string{"POSTGRES_PASSWORD=password", "POSTGRES_DB=boundarytest"},
	}

	opts := getTestOpts(t, opt...)

	resource, err := pool.RunWithOptions(dockerOptions)
	require.NoError(err)
	if !opts.skipCleanup {
		t.Cleanup(func() {
			cleanupResource(t, pool, resource)
		})
	}
	v.postgresContainer = resource

	dbUrlTemplate := fmt.Sprintf("postgres://%%s:%%s@%s/boundarytest?sslmode=disable", resource.GetHostPort("5432/tcp"))
	dburl := fmt.Sprintf(dbUrlTemplate, "postgres", "password")
	err = pool.Retry(func() error {
		var err error
		db, err := common.SqlOpen("postgres", dburl)
		if err != nil {
			return err
		}
		return db.Ping()
	})
	require.NoError(err)

	const (
		createOpened = `create table boundary_opened ( name text primary key )`
		createClosed = `create table boundary_closed ( name text primary key )`

		createVaultAccount = `create role vault with superuser login createrole password 'vault-password'`
		createOpenedRole   = `create role opened_role noinherit`
		createClosedRole   = `create role closed_role noinherit`

		grantOpenedRole = `grant select, insert, update, delete on boundary_opened to opened_role`
		grantClosedRole = `grant select, insert, update, delete on boundary_closed to closed_role`
	)

	db, err := common.SqlOpen("postgres", dburl)
	require.NoError(err)
	defer db.Close()

	exec := func(q string) {
		_, err := db.Exec(q)
		require.NoError(err, q)
	}
	exec(createOpened)
	exec(createClosed)
	exec(createVaultAccount)
	exec(createOpenedRole)
	exec(createClosedRole)
	exec(grantOpenedRole)
	exec(grantClosedRole)

	vc := v.client(t).cl

	// Mount Database
	maxTTL := 24 * time.Hour
	if t, ok := t.(*testing.T); ok {
		if deadline, ok := t.Deadline(); ok {
			maxTTL = time.Until(deadline) * 2
		}
	}

	defaultTTL := maxTTL / 2
	t.Logf("maxTTL: %s, defaultTTL: %s", maxTTL, defaultTTL)
	mountInput := &vault.MountInput{
		Type:        "database",
		Description: t.Name(),
		Config: vault.MountConfigInput{
			DefaultLeaseTTL: defaultTTL.String(),
			MaxLeaseTTL:     maxTTL.String(),
		},
	}
	mountPath := opts.mountPath
	if mountPath == "" {
		mountPath = "database/"
	}
	require.NoError(vc.Sys().Mount(mountPath, mountInput))
	policyPath := fmt.Sprintf("%s*", mountPath)
	pc := pathCapabilities{
		policyPath: createCapability | readCapability | updateCapability | deleteCapability | listCapability,
	}
	v.addPolicy(t, "database", pc)

	vaultContainer, ok := v.vaultContainer.(*dockertest.Resource)
	require.True(ok)

	t.Log(vaultContainer.GetIPInNetwork(network))

	// Configure PostgreSQL secrets engine
	connUrl := fmt.Sprintf("postgresql://{{username}}:{{password}}@%s:5432/boundarytest?sslmode=disable", resource.GetIPInNetwork(network))
	t.Log(connUrl)

	postgresConfPath := path.Join(mountPath, "config/postgresql")
	postgresConfOptions := map[string]any{
		"plugin_name":    "postgresql-database-plugin",
		"connection_url": connUrl,
		"allowed_roles":  "opened,closed",
		"username":       "vault",
		"password":       "vault-password",
	}
	s, err := vc.Logical().Write(postgresConfPath, postgresConfOptions)
	require.NoError(err)
	require.Empty(s)

	const (
		vaultOpenedCreationStatement = `
create role "{{name}}"
with login password '{{password}}'
valid until '{{expiration}}' inherit;
grant opened_role to "{{name}}";
`

		vaultClosedCreationStatement = `
create role "{{name}}"
with login password '{{password}}'
valid until '{{expiration}}' inherit;
grant closed_role to "{{name}}";
`
	)

	openedRolePath := path.Join(mountPath, "roles", "opened")
	openedRoleOptions := map[string]any{
		"db_name":             "postgresql",
		"creation_statements": vaultOpenedCreationStatement,
	}
	_, err = vc.Logical().Write(openedRolePath, openedRoleOptions)
	require.NoError(err)

	closedRolePath := path.Join(mountPath, "roles", "closed")
	closedRoleOptions := map[string]any{
		"db_name":             "postgresql",
		"creation_statements": vaultClosedCreationStatement,
	}
	_, err = vc.Logical().Write(closedRolePath, closedRoleOptions)
	require.NoError(err)

	return &TestDatabase{
		URL: TestDatabaseURL(dbUrlTemplate),
	}
}

func cleanupResource(t testing.TB, pool *dockertest.Pool, resource *dockertest.Resource) {
	t.Helper()
	var err error
	for i := 0; i < 10; i++ {
		err = pool.Purge(resource)
		if err == nil {
			return
		}
		time.Sleep(1 * time.Second)
	}

	if strings.Contains(err.Error(), "No such container") {
		return
	}
	t.Fatalf("Failed to cleanup local container: %s", err)
}
