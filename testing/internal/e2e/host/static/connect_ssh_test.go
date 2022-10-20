package static_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/boundary/api/credentials"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConnectTargetWithSshCli uses the boundary cli to create a credential using boundary's
// built-in credential store. The test attaches that credential to a target and attempts to connect
// to that target using those credentials.
func TestConnectTargetWithSshCli(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadConfig()
	require.NoError(t, err)

	boundary.AuthenticateAdminCli(t)
	newOrgId := boundary.CreateNewOrgCli(t)
	newProjectId := boundary.CreateNewProjectCli(t, newOrgId)
	newHostCatalogId := boundary.CreateNewHostCatalogCli(t, newProjectId)
	newHostSetId := boundary.CreateNewHostSetCli(t, newHostCatalogId)
	newHostId := boundary.CreateNewHostCli(t, newHostCatalogId, c.TargetIp)
	boundary.AddHostToHostSetCli(t, newHostSetId, newHostId)
	newTargetId := boundary.CreateNewTargetCli(t, newProjectId, c.TargetPort)
	boundary.AddHostSourceToTargetCli(t, newTargetId, newHostSetId)
	newCredentialStoreId := boundary.CreateNewCredentialStoreStaticCli(t, newProjectId)

	// Create credentials
	ctx := context.Background()
	output := e2e.RunCommand(ctx, "boundary", "credentials", "create", "ssh-private-key",
		"-credential-store-id", newCredentialStoreId,
		"-username", c.TargetSshUser,
		"-private-key", "file://"+c.TargetSshKeyPath,
		"-format", "json",
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newCredentialsResult credentials.CredentialCreateResult
	err = json.Unmarshal(output.Stdout, &newCredentialsResult)
	require.NoError(t, err)
	newCredentialsId := newCredentialsResult.Item.Id
	t.Logf("Created Credentials: %s", newCredentialsId)

	// Add credentials to target
	output = e2e.RunCommand(ctx, "boundary", "targets", "add-credential-sources",
		"-id", newTargetId,
		"-brokered-credential-source", newCredentialsId,
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Get credentials for target
	output = e2e.RunCommand(ctx, "boundary", "targets", "authorize-session", "-id", newTargetId, "-format", "json")
	require.NoError(t, output.Err, string(output.Stderr))
	var newSessionAuthorizationResult targets.SessionAuthorizationResult
	err = json.Unmarshal(output.Stdout, &newSessionAuthorizationResult)
	require.NoError(t, err)

	newSessionAuthorization := newSessionAuthorizationResult.Item
	retrievedUser := fmt.Sprintf("%s", newSessionAuthorization.Credentials[0].Credential["username"])
	retrievedKey := fmt.Sprintf("%s\n", newSessionAuthorization.Credentials[0].Credential["private_key"])
	assert.Equal(t, c.TargetSshUser, retrievedUser)

	k, err := os.ReadFile(c.TargetSshKeyPath)
	require.NoError(t, err)
	require.Equal(t, string(k), retrievedKey)
	t.Log("Successfully retrieved credentials for target")

	// Connect to target and print host's IP address using retrieved credentials
	output = e2e.RunCommand(ctx, "boundary", "connect", "ssh",
		"-target-id", newTargetId, "--",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=no",
		"-o", "IdentitiesOnly=yes", // forces the use of the provided key
	)
	require.NoError(t, output.Err, string(output.Stderr))
	t.Log("Successfully connected to target")
}

// TestCreateTargetWithStaticCredentialStoreApi uses the boundary go api to create a credential using
// boundary's built-in credential store. The test then attaches that credential to a target.
func TestCreateTargetWithStaticCredentialStoreApi(t *testing.T) {
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
