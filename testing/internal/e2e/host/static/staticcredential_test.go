package static_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/hashicorp/boundary/api/credentials"
	"github.com/hashicorp/boundary/api/credentialstores"
	"github.com/hashicorp/boundary/api/hostcatalogs"
	"github.com/hashicorp/boundary/api/hosts"
	"github.com/hashicorp/boundary/api/hostsets"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConnectTargetWithStaticCredentialStoreCli uses the boundary cli to create a credential using
// boundary's built-in credential store. The test attaches that credential to a target and attempts
// to connect to that target using those credentials.
func TestConnectTargetWithStaticCredentialStoreCli(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadConfig()
	require.NoError(t, err)

	boundary.AuthenticateCli(t)

	// Create an org and project
	newOrgId := boundary.CreateNewOrgCli(t)
	t.Logf("Created Org Id: %s", newOrgId)
	newProjectId := boundary.CreateNewProjectCli(t, newOrgId)
	t.Logf("Created Project Id: %s", newProjectId)

	// Create a credential store
	output := e2e.RunCommand("boundary", "credential-stores", "create", "static",
		"-scope-id", newProjectId,
		"-format", "json",
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newCredentialStoreResult credentialstores.CredentialStoreCreateResult
	err = json.Unmarshal(output.Stdout, &newCredentialStoreResult)
	require.NoError(t, err)
	newCredentialStoreId := newCredentialStoreResult.Item.Id
	t.Logf("Created Credential Store: %s", newCredentialStoreId)

	// Create credentials
	output = e2e.RunCommand("boundary", "credentials", "create", "ssh-private-key",
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

	// Create a host catalog
	output = e2e.RunCommand("boundary", "host-catalogs", "create", "static",
		"-scope-id", newProjectId,
		"-name", "e2e Automated Test Host Catalog",
		"-format", "json",
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newHostCatalogResult hostcatalogs.HostCatalogCreateResult
	err = json.Unmarshal(output.Stdout, &newHostCatalogResult)
	require.NoError(t, err)
	newHostCatalogId := newHostCatalogResult.Item.Id
	t.Logf("Created Host Catalog: %s", newHostCatalogId)

	// Create a host set and add to catalog
	output = e2e.RunCommand("boundary", "host-sets", "create", "static",
		"-host-catalog-id", newHostCatalogId,
		"-name", "e2e Automated Test Host Set",
		"-format", "json",
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newHostSetResult hostsets.HostSetCreateResult
	err = json.Unmarshal(output.Stdout, &newHostSetResult)
	require.NoError(t, err)
	newHostSetId := newHostSetResult.Item.Id
	t.Logf("Created Host Set: %s", newHostSetId)

	// Create a host
	output = e2e.RunCommand("boundary", "hosts", "create", "static",
		"-host-catalog-id", newHostCatalogId,
		"-name", c.TargetIp,
		"-address", c.TargetIp,
		"-format", "json",
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newHostResult hosts.HostCreateResult
	err = json.Unmarshal(output.Stdout, &newHostResult)
	require.NoError(t, err)
	newHostId := newHostResult.Item.Id
	t.Logf("Created Host: %s", newHostId)

	// Add host to host set
	output = e2e.RunCommand("boundary", "host-sets", "add-hosts", "-id", newHostSetId, "-host", newHostId)
	require.NoError(t, output.Err, string(output.Stderr))

	// Create a target
	output = e2e.RunCommand("boundary", "targets", "create", "tcp",
		"-scope-id", newProjectId,
		"-default-port", c.TargetPort,
		"-name", "e2e Automated Test Target",
		"-format", "json",
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newTargetResult targets.TargetCreateResult
	err = json.Unmarshal(output.Stdout, &newTargetResult)
	require.NoError(t, err)
	newTargetId := newTargetResult.Item.Id
	t.Logf("Created Target: %s", newTargetId)

	// Add host set to target
	output = e2e.RunCommand("boundary", "targets", "add-host-sources",
		"-id", newTargetId,
		"-host-source", newHostSetId,
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Add credentials to target
	output = e2e.RunCommand("boundary", "targets", "add-credential-sources",
		"-id", newTargetId,
		"-brokered-credential-source", newCredentialsId,
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Get credentials for target
	output = e2e.RunCommand("boundary", "targets", "authorize-session", "-id", newTargetId, "-format", "json")
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
	output = e2e.RunCommand("boundary", "connect", "ssh",
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

	// Create boundary api client
	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	ctx := context.Background()

	// Create an org and project
	newOrgId := boundary.CreateNewOrgApi(t, ctx, client)
	t.Logf("Created Org Id: %s", newOrgId)
	newProjectId := boundary.CreateNewProjectApi(t, ctx, client, newOrgId)
	t.Logf("Created Project Id: %s", newProjectId)

	// Create a credential store
	csClient := credentialstores.NewClient(client)
	newCredentialStoreResult, err := csClient.Create(ctx, "static", newProjectId)
	require.NoError(t, err)
	newCredentialStoreId := newCredentialStoreResult.Item.Id
	t.Logf("Created Credential Store: %s", newCredentialStoreId)

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

	// Create a host catalog
	hcClient := hostcatalogs.NewClient(client)
	newHostCatalogResult, err := hcClient.Create(ctx, "static", newProjectId,
		hostcatalogs.WithName("e2e Automated Test Host Catalog"),
	)
	require.NoError(t, err)
	newHostCatalogId := newHostCatalogResult.Item.Id
	t.Logf("Created Host Catalog: %s", newHostCatalogId)

	// Create a host set and add to catalog
	hsClient := hostsets.NewClient(client)
	newHostSetResult, err := hsClient.Create(ctx, newHostCatalogId)
	require.NoError(t, err)
	newHostSetId := newHostSetResult.Item.Id
	t.Logf("Created Host Set: %s", newHostSetId)

	// Create a host
	hClient := hosts.NewClient(client)
	newHostResult, err := hClient.Create(ctx, newHostCatalogId,
		hosts.WithName(c.TargetIp),
		hosts.WithStaticHostAddress(c.TargetIp),
	)
	require.NoError(t, err)
	newHostId := newHostResult.Item.Id
	t.Logf("Created Host: %s", newHostId)

	// Add host to host set
	_, err = hsClient.AddHosts(ctx, newHostSetId, 0, []string{newHostId}, hostsets.WithAutomaticVersioning(true))
	require.NoError(t, err)

	// Create a target
	tClient := targets.NewClient(client)
	targetPort, err := strconv.ParseInt(c.TargetPort, 10, 32)
	require.NoError(t, err)
	newTargetResult, err := tClient.Create(ctx, "tcp", newProjectId,
		targets.WithName("e2e Automated Test Target"),
		targets.WithTcpTargetDefaultPort(uint32(targetPort)),
	)
	require.NoError(t, err)
	newTargetId := newTargetResult.Item.Id
	t.Logf("Created Target: %s", newTargetId)

	// Add host set to target
	_, err = tClient.AddHostSources(ctx, newTargetId, 0,
		[]string{newHostSetId},
		targets.WithAutomaticVersioning(true),
	)
	require.NoError(t, err)

	// Add credentials to target
	_, err = tClient.AddCredentialSources(ctx, newTargetId, 0,
		targets.WithAutomaticVersioning(true),
		targets.WithBrokeredCredentialSourceIds([]string{newCredentialsId}),
	)
	require.NoError(t, err)
}
