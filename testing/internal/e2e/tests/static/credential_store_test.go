package static_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/boundary/api/credentials"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCliStaticCredentialStore validates various credential-store operations using the cli
func TestCliStaticCredentialStore(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadConfig()
	require.NoError(t, err)

	ctx := context.Background()
	boundary.AuthenticateAdminCli(t, ctx)
	newOrgId := boundary.CreateNewOrgCli(t, ctx)
	newProjectId := boundary.CreateNewProjectCli(t, ctx, newOrgId)
	newCredentialStoreId := boundary.CreateNewCredentialStoreStaticCli(t, ctx, newProjectId)

	// Create ssh key credentials
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"credentials", "create", "ssh-private-key",
			"-credential-store-id", newCredentialStoreId,
			"-username", c.TargetSshUser,
			"-private-key", "file://"+c.TargetSshKeyPath,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var keyCredentialsResult credentials.CredentialCreateResult
	err = json.Unmarshal(output.Stdout, &keyCredentialsResult)
	require.NoError(t, err)
	keyCredentialsId := keyCredentialsResult.Item.Id
	t.Logf("Created SSH Private Key Credentials: %s", keyCredentialsId)

	// Create username/password credentials
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"credentials", "create", "username-password",
			"-credential-store-id", newCredentialStoreId,
			"-username", c.TargetSshUser,
			"-password", "env://E2E_CREDENTIALS_PASSWORD",
			"-format", "json",
		),
		e2e.WithEnv("E2E_CREDENTIALS_PASSWORD", "password"),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var pwCredentialsResult credentials.CredentialCreateResult
	err = json.Unmarshal(output.Stdout, &pwCredentialsResult)
	require.NoError(t, err)
	pwCredentialsId := pwCredentialsResult.Item.Id
	t.Logf("Created Username/Password Credentials: %s", pwCredentialsId)

	// Delete credential store
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("credential-stores", "delete", "-id", newCredentialStoreId),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	err = backoff.RetryNotify(
		func() error {
			output = e2e.RunCommand(ctx, "boundary",
				e2e.WithArgs("credential-stores", "read", "-id", newCredentialStoreId, "-format", "json"),
			)
			if output.Err == nil {
				return fmt.Errorf("Deleted credential can still be read: '%s'", output.Stdout)
			}

			var response e2e.CliError
			err = json.Unmarshal(output.Stderr, &response)
			require.NoError(t, err)
			statusCode := response.Status
			if statusCode != 404 {
				return backoff.Permanent(
					fmt.Errorf("Command did not return expected status code. Expected: 404, Actual: %d", statusCode),
				)
			}

			return nil
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(3*time.Second), 5),
		func(err error, td time.Duration) {
			t.Logf("%s. Retrying...", err.Error())
		},
	)
	require.NoError(t, err)
	t.Logf("Successfully deleted credential store")
}

// TestApiStaticCredentialStore uses the Go api to create a credential using
// boundary's built-in credential store. The test then attaches that credential to a target.
func TestApiStaticCredentialStore(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadConfig()
	require.NoError(t, err)

	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	ctx := context.Background()

	newOrgId := boundary.CreateNewOrgApi(t, ctx, client)
	newProjectId := boundary.CreateNewProjectApi(t, ctx, client, newOrgId)
	newHostCatalogId := boundary.CreateNewHostCatalogApi(t, ctx, client, newProjectId)
	newHostSetId := boundary.CreateNewHostSetApi(t, ctx, client, newHostCatalogId)
	newHostId := boundary.CreateNewHostApi(t, ctx, client, newHostCatalogId, c.TargetIp)
	boundary.AddHostToHostSetApi(t, ctx, client, newHostSetId, newHostId)
	newTargetId := boundary.CreateNewTargetApi(t, ctx, client, newProjectId, c.TargetPort)
	boundary.AddHostSourceToTargetApi(t, ctx, client, newTargetId, newHostSetId)
	newCredentialStoreId := boundary.CreateNewCredentialStoreStaticApi(t, ctx, client, newProjectId)

	// Create credentials
	cClient := credentials.NewClient(client)
	k, err := os.ReadFile(c.TargetSshKeyPath)
	require.NoError(t, err)
	newCredentialsResult, err := cClient.Create(ctx, "ssh_private_key", newCredentialStoreId,
		credentials.WithSshPrivateKeyCredentialUsername(c.TargetSshUser),
		credentials.WithSshPrivateKeyCredentialPrivateKey(string(k)),
	)
	require.NoError(t, err)
	newCredentialsId := newCredentialsResult.Item.Id
	t.Logf("Created Credentials: %s", newCredentialsId)

	// Add credentials to target
	tClient := targets.NewClient(client)
	_, err = tClient.AddCredentialSources(ctx, newTargetId, 0,
		targets.WithAutomaticVersioning(true),
		targets.WithBrokeredCredentialSourceIds([]string{newCredentialsId}),
	)
	require.NoError(t, err)

	// Authorize Session
	newSessionAuthorizationResult, err := tClient.AuthorizeSession(ctx, newTargetId)
	require.NoError(t, err)
	newSessionAuthorization := newSessionAuthorizationResult.Item
	retrievedUser := fmt.Sprintf("%s", newSessionAuthorization.Credentials[0].Credential["username"])
	retrievedKey := fmt.Sprintf("%s", newSessionAuthorization.Credentials[0].Credential["private_key"])
	assert.Equal(t, c.TargetSshUser, retrievedUser)
	require.Equal(t, string(k), retrievedKey)
	t.Log("Successfully retrieved credentials for target")
}
