package database_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api/credentiallibraries"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/hashicorp/boundary/testing/internal/e2e/infra"
	"github.com/hashicorp/boundary/testing/internal/e2e/vault"
	_ "github.com/jackc/pgx/v4/stdlib"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"
)

type TestEnvironment struct {
	Pool       *dockertest.Pool
	Network    *dockertest.Network
	Boundary   *infra.Container
	Database   *infra.Container
	Target     *infra.Container
	DbInitInfo boundary.DbInitInfo
}

// TestDatabaseMigration tests migrating the Boundary database from the latest released version to
// the version under test. It creates a database, populates the database with a number of resources,
// and uses the Boundary version under test to migrate the database.
func TestDatabaseMigration(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadConfig()
	require.NoError(t, err)

	ctx := context.Background()
	te := setupEnvironment(t, ctx, c)
	populateBoundaryDatabase(t, ctx, c, te)

	// Migrate database
	t.Log("Stopping boundary before migrating...")
	err = te.Pool.Client.StopContainer(te.Boundary.Resource.Container.ID, 10)
	require.NoError(t, err)

	bonfigFilePath, err := filepath.Abs("testdata/boundary-config.hcl")
	require.NoError(t, err)

	t.Log("Starting database migration...")
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("database", "migrate", "-config", bonfigFilePath),
		e2e.WithEnv("BOUNDARY_POSTGRES_URL", te.Database.UriLocalhost),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	t.Logf("%s", output.Stdout)
	t.Logf("Migration Output: %s", output.Stderr)
}

func setupEnvironment(t testing.TB, ctx context.Context, c *config) TestEnvironment {
	pool, err := dockertest.NewPool("")
	require.NoError(t, err)
	err = pool.Client.Ping()
	require.NoError(t, err)

	// This ensures that the latest Boundary image is used
	err = pool.Client.PullImage(docker.PullImageOptions{
		Repository: "hashicorp/boundary",
		Tag:        "latest",
	}, docker.AuthConfiguration{})
	require.NoError(t, err)

	// Set up docker network
	network, err := pool.CreateNetwork(t.Name())
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, pool.RemoveNetwork(network))
	})

	// Start a Boundary database and wait until it's ready
	db := infra.StartBoundaryDatabase(t, pool, network)
	t.Cleanup(func() {
		pool.Purge(db.Resource)
	})

	pool.MaxWait = 10 * time.Second
	t.Log("Waiting for database to load...")
	err = pool.Retry(func() error {
		db, err := sql.Open("pgx", db.UriLocalhost)
		if err != nil {
			return err
		}
		return db.Ping()
	})
	require.NoError(t, err)

	// Create a target
	target := infra.StartOpenSshServer(t, pool, network, c.TargetSshUser, c.TargetSshKeyPath)
	t.Cleanup(func() {
		pool.Purge(target.Resource)
	})

	// Initialize the database and extract resulting information
	dbInit := infra.InitBoundaryDatabase(t, pool, network, db.UriNetwork)
	t.Cleanup(func() {
		pool.Purge(dbInit.Resource)
	})
	dbInitInfo := infra.GetDbInitInfoFromContainer(t, pool, dbInit)

	// Start a Boundary server and wait until Boundary has finished loading
	b := infra.StartBoundary(t, pool, network, db.UriNetwork)
	t.Cleanup(func() {
		pool.Purge(b.Resource)
	})

	buf := bytes.NewBuffer(nil)
	ebuf := bytes.NewBuffer(nil)
	_, err = b.Resource.Exec([]string{"boundary", "version"}, dockertest.ExecOptions{
		StdOut: buf,
		StdErr: ebuf,
	})
	require.NoError(t, err)
	require.Empty(t, ebuf)
	t.Logf("Using Boundary Version: %s", buf.String())

	t.Log("Waiting for Boundary to finish loading...")
	err = pool.Retry(func() error {
		response, err := http.Get(b.UriLocalhost)
		if err != nil {
			t.Logf("Could not access Boundary URL: %s. Retrying...", err.Error())
			return err
		}

		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("Could not connect to %s. Status Code: %d", b.UriLocalhost, response.StatusCode)
		}

		return nil
	})
	require.NoError(t, err)

	return TestEnvironment{
		Pool:       pool,
		Network:    network,
		Boundary:   b,
		Database:   db,
		Target:     target,
		DbInitInfo: dbInitInfo,
	}
}

func populateBoundaryDatabase(t testing.TB, ctx context.Context, c *config, te TestEnvironment) {
	os.Setenv("BOUNDARY_ADDR", te.Boundary.UriLocalhost)
	os.Setenv("E2E_PASSWORD_AUTH_METHOD_ID", te.DbInitInfo.AuthMethod.AuthMethodId)
	os.Setenv("E2E_PASSWORD_ADMIN_LOGIN_NAME", te.DbInitInfo.AuthMethod.LoginName)
	os.Setenv("E2E_PASSWORD_ADMIN_PASSWORD", te.DbInitInfo.AuthMethod.Password)

	// Create resources for target. Uses the local CLI so that these methods can be reused.
	// While the CLI version used won't necessarily match the controller version, it should be (and is
	// supposed to be) backwards ompatible
	boundary.AuthenticateAdminCli(t, ctx)
	newOrgId := boundary.CreateNewOrgCli(t, ctx)
	newProjectId := boundary.CreateNewProjectCli(t, ctx, newOrgId)
	newHostCatalogId := boundary.CreateNewHostCatalogCli(t, ctx, newProjectId)
	newHostSetId := boundary.CreateNewHostSetCli(t, ctx, newHostCatalogId)
	newHostId := boundary.CreateNewHostCli(t, ctx, newHostCatalogId, te.Target.UriNetwork)
	boundary.AddHostToHostSetCli(t, ctx, newHostSetId, newHostId)
	newTargetId := boundary.CreateNewTargetCli(t, ctx, newProjectId, "2222") // openssh-server uses port 2222
	boundary.AddHostSourceToTargetCli(t, ctx, newTargetId, newHostSetId)

	// Create AWS dynamic host catalog
	newAwsHostCatalogId := boundary.CreateNewAwsHostCatalogCli(t, ctx, newProjectId, c.AwsAccessKeyId, c.AwsSecretAccessKey)
	newAwsHostSetId := boundary.CreateNewAwsHostSetCli(t, ctx, newAwsHostCatalogId, c.AwsHostSetFilter)
	boundary.WaitForHostsInHostSetCli(t, ctx, newAwsHostSetId)

	// Create static credentials
	newCredentialStoreId := boundary.CreateNewCredentialStoreStaticCli(t, ctx, newProjectId)
	boundary.CreateNewStaticCredentialPasswordCli(t, ctx, newCredentialStoreId, c.TargetSshUser, "password")
	boundary.CreateNewStaticCredentialJsonCli(t, ctx, newCredentialStoreId, "testdata/credential.json")
	newCredentialsId := boundary.CreateNewStaticCredentialPrivateKeyCli(t, ctx, newCredentialStoreId, c.TargetSshUser, c.TargetSshKeyPath)
	boundary.AddCredentialSourceToTargetCli(t, ctx, newTargetId, newCredentialsId)

	// Create vault credentials
	vaultAddr, boundaryPolicyName, kvPolicyFilePath := vault.Setup(t)
	t.Cleanup(func() {
		output := e2e.RunCommand(ctx, "vault",
			e2e.WithArgs("policy", "delete", boundaryPolicyName),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	output := e2e.RunCommand(ctx, "vault",
		e2e.WithArgs("secrets", "enable", "-path="+c.VaultSecretPath, "kv-v2"),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	t.Cleanup(func() {
		output := e2e.RunCommand(ctx, "vault",
			e2e.WithArgs("secrets", "disable", c.VaultSecretPath),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	privateKeySecretName := vault.CreateKvPrivateKeyCredential(t, c.VaultSecretPath, c.TargetSshUser, c.TargetSshKeyPath, kvPolicyFilePath)
	kvPolicyName := vault.WritePolicy(t, ctx, kvPolicyFilePath)
	t.Cleanup(func() {
		output := e2e.RunCommand(ctx, "vault",
			e2e.WithArgs("policy", "delete", kvPolicyName),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	t.Log("Created Vault Credential")
	output = e2e.RunCommand(ctx, "vault",
		e2e.WithArgs(
			"token", "create",
			"-no-default-policy=true",
			"-policy="+boundaryPolicyName,
			"-policy="+kvPolicyName,
			"-orphan=true",
			"-period=20m",
			"-renewable=true",
			"-format=json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var tokenCreateResult vault.CreateTokenResponse
	err := json.Unmarshal(output.Stdout, &tokenCreateResult)
	require.NoError(t, err)
	credStoreToken := tokenCreateResult.Auth.Client_Token
	t.Log("Created Vault Cred Store Token")
	newVaultCredentialStoreId := boundary.CreateNewCredentialStoreVaultCli(t, ctx, newProjectId, vaultAddr, credStoreToken)
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"credential-libraries", "create", "vault",
			"-credential-store-id", newVaultCredentialStoreId,
			"-vault-path", c.VaultSecretPath+"/data/"+privateKeySecretName,
			"-name", "e2e Automated Test Vault Credential Library",
			"-credential-type", "ssh_private_key",
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newCredentialLibraryResult credentiallibraries.CredentialLibraryCreateResult
	err = json.Unmarshal(output.Stdout, &newCredentialLibraryResult)
	require.NoError(t, err)
	newCredentialLibraryId := newCredentialLibraryResult.Item.Id
	t.Logf("Created Credential Library: %s", newCredentialLibraryId)

	// Create a session. Uses Boundary in a docker container to do the connect in order to avoid
	// modifying the runner's /etc/hosts file. Otherwise, you would need to add a `127.0.0.1
	// localhost boundary` entry into /etc/hosts.
	buf := bytes.NewBuffer(nil)
	ebuf := bytes.NewBuffer(nil)
	_, err = te.Boundary.Resource.Exec(
		[]string{
			"boundary", "authenticate", "password",
			"-addr", te.Boundary.UriNetwork,
			"-auth-method-id", te.DbInitInfo.AuthMethod.AuthMethodId,
			"-login-name", te.DbInitInfo.AuthMethod.LoginName,
			"-password", "env://E2E_TEST_BOUNDARY_PASSWORD",
			"-format", "json",
		},
		dockertest.ExecOptions{
			StdOut: buf,
			StdErr: ebuf,
			Env:    []string{"E2E_TEST_BOUNDARY_PASSWORD=" + te.DbInitInfo.AuthMethod.Password},
		},
	)
	require.NoError(t, err)
	require.Empty(t, ebuf)
	var authenticationResult boundary.AuthenticateCliOutput
	err = json.Unmarshal(buf.Bytes(), &authenticationResult)
	require.NoError(t, err)
	auth_token, ok := authenticationResult.Item.Attributes["token"].(string)
	require.True(t, ok)

	connectTarget := infra.ConnectToTarget(t, te.Pool, te.Network, te.Boundary.UriNetwork, auth_token, newTargetId)
	t.Cleanup(func() {
		te.Pool.Purge(connectTarget.Resource)
	})
	_, err = te.Pool.Client.WaitContainer(connectTarget.Resource.Container.ID)
	require.NoError(t, err)
	buf = bytes.NewBuffer(nil)
	ebuf = bytes.NewBuffer(nil)
	err = te.Pool.Client.Logs(docker.LogsOptions{
		Container:    connectTarget.Resource.Container.ID,
		OutputStream: buf,
		ErrorStream:  ebuf,
		Follow:       true,
		Stdout:       true,
		Stderr:       true,
	})
	require.NoError(t, err)
	require.Empty(t, ebuf)
	t.Log("Created session")
}
