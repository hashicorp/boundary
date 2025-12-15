// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

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

	"github.com/hashicorp/boundary/api/workers"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/hashicorp/boundary/testing/internal/e2e/infra"
	"github.com/hashicorp/boundary/testing/internal/e2e/vault"
	_ "github.com/jackc/pgx/v5/stdlib"
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
	Vault      *infra.Container
	DbInitInfo boundary.DbInitInfo
}

// TestDatabaseMigration tests migrating the Boundary database from the latest released version to
// the version under test. It creates a database, populates the database with a number of resources,
// and uses the Boundary version under test to migrate the database.
func TestDatabaseMigration(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
	require.NoError(t, err)

	ctx := t.Context()

	boundaryRepo := "hashicorp/boundary"
	boundaryTag := "latest"
	te := setupEnvironment(t, c, boundaryRepo, boundaryTag)
	populateBoundaryDatabase(t, ctx, c, te, boundaryRepo, boundaryTag)

	// Migrate database
	t.Log("Stopping boundary before migrating...")
	err = te.Pool.Client.StopContainer(te.Boundary.Resource.Container.ID, 10)
	require.NoError(t, err)

	output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("version"))
	require.NoError(t, err)
	t.Logf("Upgrading to version: %s", output.Stdout)

	bConfigFilePath, err := filepath.Abs("testdata/boundary-config.hcl")
	require.NoError(t, err)

	t.Log("Starting database migration...")
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("database", "migrate", "-config", bConfigFilePath),
		e2e.WithEnv("BOUNDARY_POSTGRES_URL", te.Database.UriLocalhost),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	t.Logf("%s", output.Stdout)
	t.Logf("Migration Output: %s", output.Stderr)
}

func setupEnvironment(t testing.TB, c *config, boundaryRepo, boundaryTag string) TestEnvironment {
	pool, err := dockertest.NewPool("")
	require.NoError(t, err)
	err = pool.Client.Ping()
	require.NoError(t, err)
	pool.MaxWait = 10 * time.Second

	// Set up docker network
	network, err := pool.CreateNetwork(t.Name())
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, pool.RemoveNetwork(network))
	})

	// Start Vault
	v, vaultToken := infra.StartVault(t, pool, network, "hashicorp/vault", "latest")
	t.Cleanup(func() {
		if err := pool.Purge(v.Resource); err != nil {
			t.Logf("error purging pool: %v", err)
		}
	})
	os.Setenv("VAULT_ADDR", v.UriLocalhost)
	os.Setenv("VAULT_TOKEN", vaultToken)
	t.Log("Waiting for Vault to finish loading...")
	err = pool.Retry(func() error {
		response, err := http.Get(v.UriLocalhost)
		if err != nil {
			t.Logf("Could not access Vault URL: %s. Retrying...", err.Error())
			return err
		}
		defer response.Body.Close()

		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("Could not connect to %s. Status Code: %d", v.UriLocalhost, response.StatusCode)
		}

		return nil
	})
	require.NoError(t, err)

	// Start a Boundary database and wait until it's ready
	db := infra.StartBoundaryDatabase(t, pool, network, "library/postgres", "latest")
	t.Cleanup(func() {
		if err := pool.Purge(db.Resource); err != nil {
			t.Logf("error purging pool: %v", err)
		}
	})
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
	target := infra.StartOpenSshServer(
		t,
		pool,
		network,
		"linuxserver/openssh-server",
		"latest",
		c.TargetSshUser,
		c.TargetSshKeyPath,
	)
	t.Cleanup(func() {
		if err := pool.Purge(target.Resource); err != nil {
			t.Logf("error purging pool: %v", err)
		}
	})

	// Initialize the database and extract resulting information
	dbInit := infra.InitBoundaryDatabase(
		t,
		pool,
		network,
		boundaryRepo,
		boundaryTag,
		db.UriNetwork,
	)
	t.Cleanup(func() {
		if err := pool.Purge(dbInit.Resource); err != nil {
			t.Logf("error purging pool: %v", err)
		}
	})
	dbInitInfo := infra.GetDbInitInfoFromContainer(t, pool, dbInit)

	// Start a Boundary server and wait until Boundary has finished loading
	b := infra.StartBoundary(t, pool, network, boundaryRepo, boundaryTag, db.UriNetwork)
	t.Cleanup(func() {
		if err := pool.Purge(b.Resource); err != nil {
			t.Logf("error purging pool: %v", err)
		}
	})
	os.Setenv("BOUNDARY_ADDR", b.UriLocalhost)

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
		response, err := http.Get(fmt.Sprintf("%s/health", b.UriLocalhost))
		if err != nil {
			t.Logf("Could not access health endpoint: %s. Retrying...", err.Error())
			return err
		}

		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("Health check returned an error. Status Code: %d", response.StatusCode)
		}

		response.Body.Close()
		return nil
	})
	require.NoError(t, err)

	return TestEnvironment{
		Pool:       pool,
		Network:    network,
		Boundary:   b,
		Database:   db,
		Target:     target,
		Vault:      v,
		DbInitInfo: dbInitInfo,
	}
}

func populateBoundaryDatabase(t testing.TB, ctx context.Context, c *config, te TestEnvironment, boundaryRepo, boundaryTag string) {
	// Create resources for target. Uses the local CLI so that these methods can be reused.
	// While the CLI version used won't necessarily match the controller version, it should be (and is
	// supposed to be) backwards compatible
	boundary.AuthenticateCli(t, ctx, te.DbInitInfo.AuthMethod.AuthMethodId, te.DbInitInfo.AuthMethod.LoginName, te.DbInitInfo.AuthMethod.Password)
	orgId, err := boundary.CreateOrgCli(t, ctx)
	require.NoError(t, err)
	projectId, err := boundary.CreateProjectCli(t, ctx, orgId)
	require.NoError(t, err)
	hostCatalogId, err := boundary.CreateHostCatalogCli(t, ctx, projectId)
	require.NoError(t, err)
	hostSetId, err := boundary.CreateHostSetCli(t, ctx, hostCatalogId)
	require.NoError(t, err)
	hostId, err := boundary.CreateHostCli(t, ctx, hostCatalogId, te.Target.UriNetwork)
	require.NoError(t, err)
	err = boundary.AddHostToHostSetCli(t, ctx, hostSetId, hostId)
	require.NoError(t, err)
	targetId, err := boundary.CreateTargetCli(t, ctx, projectId, "2222", nil) // openssh-server uses port 2222
	require.NoError(t, err)
	err = boundary.AddHostSourceToTargetCli(t, ctx, targetId, hostSetId)
	require.NoError(t, err)

	// Create a target with an address attached
	_, err = boundary.CreateTargetCli(
		t,
		ctx,
		projectId,
		"2222",
		[]target.Option{
			target.WithName("e2e target with address"),
			target.WithAddress(te.Target.UriNetwork),
		},
	)
	require.NoError(t, err)

	// Create AWS dynamic host catalog
	awsHostCatalogId, err := boundary.CreateAwsHostCatalogCli(t, ctx, projectId, c.AwsAccessKeyId, c.AwsSecretAccessKey, c.AwsRegion, false)
	require.NoError(t, err)
	awsHostSetId, err := boundary.CreatePluginHostSetCli(t, ctx, awsHostCatalogId, c.AwsHostSetFilter, "4")
	require.NoError(t, err)
	boundary.WaitForHostsInHostSetCli(t, ctx, awsHostSetId)

	// Create a user/group and add role to group
	accountId, _, err := boundary.CreateAccountCli(t, ctx, te.DbInitInfo.AuthMethod.AuthMethodId, "test-account")
	require.NoError(t, err)
	userId, err := boundary.CreateUserCli(t, ctx, "global")
	require.NoError(t, err)
	err = boundary.SetAccountToUserCli(t, ctx, userId, accountId)
	require.NoError(t, err)
	groupId, err := boundary.CreateGroupCli(t, ctx, "global")
	require.NoError(t, err)
	err = boundary.AddUserToGroup(t, ctx, userId, groupId)
	require.NoError(t, err)
	roleId, err := boundary.CreateRoleCli(t, ctx, projectId)
	require.NoError(t, err)
	err = boundary.AddGrantToRoleCli(t, ctx, roleId, "ids=*;type=target;actions=authorize-session")
	require.NoError(t, err)
	err = boundary.AddPrincipalToRoleCli(t, ctx, roleId, groupId)
	require.NoError(t, err)

	// Create static credentials
	storeId, err := boundary.CreateCredentialStoreStaticCli(t, ctx, projectId)
	require.NoError(t, err)
	_, err = boundary.CreateStaticCredentialUsernamePasswordCli(t, ctx, storeId, c.TargetSshUser, "password")
	require.NoError(t, err)
	_, err = boundary.CreateStaticCredentialJsonCli(t, ctx, storeId, "testdata/credential.json")
	require.NoError(t, err)
	credentialsId, err := boundary.CreateStaticCredentialPrivateKeyCli(t, ctx, storeId, c.TargetSshUser, c.TargetSshKeyPath)
	require.NoError(t, err)
	err = boundary.AddBrokeredCredentialSourceToTargetCli(t, ctx, targetId, credentialsId)
	require.NoError(t, err)

	// Create vault credentials
	boundaryPolicyName := vault.SetupForBoundaryController(t, "testdata/boundary-controller-policy.hcl")
	output := e2e.RunCommand(ctx, "vault",
		e2e.WithArgs("secrets", "enable", "-path="+c.VaultSecretPath, "kv-v2"),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	privateKeySecretName, privateKeyPolicyName := vault.CreateKvPrivateKeyCredential(t, c.VaultSecretPath, c.TargetSshUser, c.TargetSshKeyPath)
	t.Cleanup(func() {
		ctx := context.Background()
		output := e2e.RunCommand(ctx, "vault",
			e2e.WithArgs("policy", "delete", privateKeyPolicyName),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})

	passwordSecretName, passwordPolicyName, _ := vault.CreateKvPasswordCredential(t, c.VaultSecretPath, c.TargetSshUser)
	t.Cleanup(func() {
		ctx := context.Background()
		output := e2e.RunCommand(ctx, "vault",
			e2e.WithArgs("policy", "delete", passwordPolicyName),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	t.Log("Created Vault Credential")

	output = e2e.RunCommand(ctx, "vault",
		e2e.WithArgs(
			"token", "create",
			"-no-default-policy=true",
			"-policy="+boundaryPolicyName,
			"-policy="+privateKeyPolicyName,
			"-policy="+passwordPolicyName,
			"-orphan=true",
			"-period=20m",
			"-renewable=true",
			"-format=json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var tokenCreateResult vault.CreateTokenResponse
	err = json.Unmarshal(output.Stdout, &tokenCreateResult)
	require.NoError(t, err)
	credStoreToken := tokenCreateResult.Auth.Client_Token
	t.Log("Created Vault Cred Store Token")

	// Create a credential store for vault
	vaultStoreId, err := boundary.CreateCredentialStoreVaultCli(t, ctx, projectId, te.Vault.UriNetwork, credStoreToken)
	require.NoError(t, err)

	// Create a credential library for the private key in vault
	_, err = boundary.CreateVaultGenericCredentialLibraryCli(
		t,
		ctx,
		vaultStoreId,
		fmt.Sprintf("%s/data/%s", c.VaultSecretPath, privateKeySecretName),
		"ssh_private_key",
	)
	require.NoError(t, err)

	// Create a credential library for the password in vault
	_, err = boundary.CreateVaultGenericCredentialLibraryCli(
		t,
		ctx,
		vaultStoreId,
		fmt.Sprintf("%s/data/%s", c.VaultSecretPath, passwordSecretName),
		"username_password",
	)
	require.NoError(t, err)

	// Create a worker
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"workers", "create", "controller-led",
			"-name", "e2e worker",
			"-description", "e2e",
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newWorkerResult workers.WorkerCreateResult
	err = json.Unmarshal(output.Stdout, &newWorkerResult)
	require.NoError(t, err)
	newWorkerId := newWorkerResult.Item.Id
	t.Logf("Created Worker: %s", newWorkerId)

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
			"-keyring-type", "none",
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

	connectTarget := infra.ConnectToTarget(
		t,
		te.Pool,
		te.Network,
		boundaryRepo,
		boundaryTag,
		te.Boundary.UriNetwork,
		auth_token,
		targetId,
	)
	t.Cleanup(func() {
		if err := te.Pool.Purge(connectTarget.Resource); err != nil {
			t.Logf("error purging pool: %v", err)
		}
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
