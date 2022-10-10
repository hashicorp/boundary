package vault_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/api/credentiallibraries"
	"github.com/hashicorp/boundary/api/credentialstores"
	"github.com/hashicorp/boundary/api/hostcatalogs"
	"github.com/hashicorp/boundary/api/hosts"
	"github.com/hashicorp/boundary/api/hostsets"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/hashicorp/boundary/testing/internal/e2e/vault"
	"github.com/kelseyhightower/envconfig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type config struct {
	TargetIp         string `envconfig:"E2E_TARGET_IP" required:"true"`    // e.g. 192.168.0.1
	TargetSshUser    string `envconfig:"E2E_SSH_USER" required:"true"`     // e.g. ubuntu
	TargetSshKeyPath string `envconfig:"E2E_SSH_KEY_PATH" required:"true"` // e.g. /Users/username/key.pem
	TargetPort       string `envconfig:"E2E_SSH_PORT" default:"22"`
	VaultSecretPath  string `envconfig:"E2E_VAULT_SECRET_PATH" default:"e2e_secrets"`
}

func loadConfig() (*config, error) {
	var c config
	err := envconfig.Process("", &c)
	if err != nil {
		return nil, err
	}

	return &c, err
}

type createTokenResponse struct {
	Auth struct {
		Client_Token string
	}
}

// TestCreateVaultCredentialStoreCli uses the boundary and vault clis to add secrets management
// for a target. The test sets up vault as a credential store, creates a set of credentials
// in vault to be attached to a target, and attempts to connect to that target using those
// credentials.
func TestCreateVaultCredentialStoreCli(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadConfig()
	require.NoError(t, err)

	// Configure vault
	vaultAddr, boundaryPolicyName := vault.Setup(t)

	output := e2e.RunCommand("vault", "secrets", "enable", "-path="+c.VaultSecretPath, "kv-v2")
	require.NoError(t, output.Err, string(output.Stderr))
	t.Cleanup(func() {
		output := e2e.RunCommand("vault", "secrets", "disable", c.VaultSecretPath)
		require.NoError(t, output.Err, string(output.Stderr))
	})

	// Create credential in vault
	secretName := "TestCreateVaultCredentialStoreCli"
	credentialPolicyName := vault.CreateKvPrivateKeyCredential(t, secretName, c.VaultSecretPath, c.TargetSshUser, c.TargetSshKeyPath)
	t.Log("Created Vault Credential")

	// Create vault token for boundary
	output = e2e.RunCommand("vault", "token", "create",
		"-no-default-policy=true",
		"-policy="+boundaryPolicyName,
		"-policy="+credentialPolicyName,
		"-orphan=true",
		"-period=20m",
		"-renewable=true",
		"-format=json",
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var tokenCreateResult createTokenResponse
	err = json.Unmarshal(output.Stdout, &tokenCreateResult)
	require.NoError(t, err)
	credStoreToken := tokenCreateResult.Auth.Client_Token
	t.Log("Created Vault Cred Store Token")

	// Authenticate boundary cli
	boundary.AuthenticateCli(t)

	// Create an org and project
	newOrgId := boundary.CreateNewOrgCli(t)
	t.Logf("Created Org Id: %s", newOrgId)
	newProjectId := boundary.CreateNewProjectCli(t, newOrgId)
	t.Logf("Created Project Id: %s", newProjectId)

	// Create a credential store
	output = e2e.RunCommand("boundary", "credential-stores", "create", "vault",
		"-scope-id", newProjectId,
		"-vault-address", vaultAddr,
		"-vault-token", credStoreToken,
		"-format", "json",
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newCredentialStoreResult credentialstores.CredentialStoreCreateResult
	err = json.Unmarshal(output.Stdout, &newCredentialStoreResult)
	require.NoError(t, err)
	newCredentialStoreId := newCredentialStoreResult.Item.Id
	t.Logf("Created Credential Store: %s", newCredentialStoreId)

	// Create a credential library
	output = e2e.RunCommand("boundary", "credential-libraries", "create", "vault",
		"-credential-store-id", newCredentialStoreId,
		"-vault-path", c.VaultSecretPath+"/data/"+secretName,
		"-name", "e2e Automated Test Vault Credential Library",
		"-credential-type", "ssh_private_key",
		"-format", "json",
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newCredentialLibraryResult credentiallibraries.CredentialLibraryCreateResult
	err = json.Unmarshal(output.Stdout, &newCredentialLibraryResult)
	require.NoError(t, err)
	newCredentialLibraryId := newCredentialLibraryResult.Item.Id
	t.Logf("Created Credential Library: %s", newCredentialLibraryId)

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
	output = e2e.RunCommand("boundary", "host-sets", "add-hosts",
		"-id", newHostSetId,
		"-host", newHostId,
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Create Target
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

	// Add brokered credentials to target
	output = e2e.RunCommand("boundary", "targets", "add-credential-sources",
		"-id", newTargetId,
		"-brokered-credential-source", newCredentialLibraryId,
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
	retrievedKey := fmt.Sprintf("%s", newSessionAuthorization.Credentials[0].Credential["private_key"])
	assert.Equal(t, c.TargetSshUser, retrievedUser)

	k, err := os.ReadFile(c.TargetSshKeyPath)
	require.NoError(t, err)
	require.Equal(t, string(k), retrievedKey)
	t.Log("Successfully retrieved credentials for target")

	// Create key file
	retrievedKeyPath := fmt.Sprintf("%s/%s", t.TempDir(), "target_private_key.pem")
	f, err := os.Create(retrievedKeyPath)
	require.NoError(t, err)
	_, err = f.WriteString(retrievedKey)
	require.NoError(t, err)
	err = os.Chmod(retrievedKeyPath, 0o400)
	require.NoError(t, err)

	// Connect to target and print host's IP address using retrieved credentials
	output = e2e.RunCommand("boundary", "connect",
		"-target-id", newTargetId,
		"-exec", "/usr/bin/ssh", "--",
		"-l", retrievedUser,
		"-i", retrievedKeyPath,
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=no",
		"-o", "IdentitiesOnly=yes", // forces the use of the provided key
		"-p", "{{boundary.port}}", // this is provided by boundary
		"{{boundary.ip}}",
		"hostname", "-i",
	)
	require.NoError(t, output.Err, string(output.Stderr))

	parts := strings.Fields(string(output.Stdout))
	hostIp := parts[len(parts)-1]
	require.Equal(t, c.TargetIp, hostIp, "SSH session did not return expected output")
	t.Log("Successfully connected to target")
}

// TestCreateVaultCredentialStoreApi uses the boundary go api along with the vault cli to
// add secrets management for a target. The test sets up vault as a credential stores and creates
// a set of credentials in vault that is attached to a target.
func TestCreateVaultCredentialStoreApi(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadConfig()
	require.NoError(t, err)

	// Configure vault
	vaultAddr, boundaryPolicyName := vault.Setup(t)

	output := e2e.RunCommand("vault", "secrets", "enable", "-path="+c.VaultSecretPath, "kv-v2")
	require.NoError(t, output.Err, string(output.Stderr))
	t.Cleanup(func() {
		output := e2e.RunCommand("vault", "secrets", "disable", c.VaultSecretPath)
		require.NoError(t, output.Err, string(output.Stderr))
	})

	// Create credential in vault
	secretName := "TestCreateVaultCredentialStoreCli"
	credentialPolicyName := vault.CreateKvPrivateKeyCredential(t, secretName, c.VaultSecretPath, c.TargetSshUser, c.TargetSshKeyPath)
	t.Log("Created Vault Credential")

	// Create vault token for boundary
	output = e2e.RunCommand("vault", "token", "create",
		"-no-default-policy=true",
		"-policy="+boundaryPolicyName,
		"-policy="+credentialPolicyName,
		"-orphan=true",
		"-period=20m",
		"-renewable=true",
		"-format=json",
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var tokenCreateResult createTokenResponse
	err = json.Unmarshal(output.Stdout, &tokenCreateResult)
	credStoreToken := tokenCreateResult.Auth.Client_Token
	t.Log("Created Vault Cred Store Token")

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
	newCredentialStoreResult, err := csClient.Create(ctx, "vault", newProjectId,
		credentialstores.WithVaultCredentialStoreAddress(vaultAddr),
		credentialstores.WithVaultCredentialStoreToken(credStoreToken),
	)
	require.NoError(t, err)
	newCredentialStoreId := newCredentialStoreResult.Item.Id
	t.Logf("Created Credential Store: %s", newCredentialStoreId)

	// Create a credential library
	clClient := credentiallibraries.NewClient(client)
	newCredentialLibraryResult, err := clClient.Create(ctx, newCredentialStoreId,
		credentiallibraries.WithVaultCredentialLibraryPath(c.VaultSecretPath+"/data/"+secretName),
		credentiallibraries.WithCredentialType("ssh_private_key"),
	)
	require.NoError(t, err)
	newCredentialLibraryId := newCredentialLibraryResult.Item.Id
	t.Logf("Created Credential Library: %s", newCredentialLibraryId)

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

	// Add brokered credentials to target
	_, err = tClient.AddCredentialSources(ctx, newTargetId, 0,
		targets.WithBrokeredCredentialSourceIds([]string{newCredentialLibraryId}),
		targets.WithAutomaticVersioning(true),
	)
	require.NoError(t, err)

	// Get credentials for target
	newSessionAuthorizationResult, err := tClient.AuthorizeSession(ctx, newTargetId)
	require.NoError(t, err)
	newSessionAuthorization := newSessionAuthorizationResult.Item
	retrievedUser, ok := newSessionAuthorization.Credentials[0].Credential["username"].(string)
	require.True(t, ok)
	assert.Equal(t, c.TargetSshUser, retrievedUser)

	retrievedKey, ok := newSessionAuthorization.Credentials[0].Credential["private_key"].(string)
	require.True(t, ok)
	k, err := os.ReadFile(c.TargetSshKeyPath)
	require.NoError(t, err)
	keysMatch := string(k) == retrievedKey // This is done to prevent printing out key info
	require.True(t, keysMatch, "Key retrieved from vault does not match expected value")
	t.Log("Successfully retrieved credentials for target")
}
