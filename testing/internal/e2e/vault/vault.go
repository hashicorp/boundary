// Package vault provides methods for commonly used vault actions that are used in end-to-end tests.
package vault

import (
	"context"
	"embed"
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/kelseyhightower/envconfig"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/boundary-controller-policy.hcl
var boundaryPolicyFile embed.FS

type config struct {
	VaultAddr  string `envconfig:"VAULT_ADDR" required:"true"` // e.g. "http://127.0.0.1:8200"
	VaultToken string `envconfig:"VAULT_TOKEN" required:"true"`
}

func loadConfig() (*config, error) {
	var c config
	err := envconfig.Process("", &c)
	if err != nil {
		return nil, err
	}

	return &c, err
}

// Setup verifies if appropriate credentials are set and adds the boundary controller
// policy to vault. Returns the vault address.
func Setup(t testing.TB) (vaultAddr string, boundaryPolicyName string, kvPolicyFilePath string) {
	c, err := loadConfig()
	require.NoError(t, err)
	vaultAddr = c.VaultAddr

	// Set up boundary policy
	data, err := boundaryPolicyFile.ReadFile("testdata/boundary-controller-policy.hcl")
	require.NoError(t, err)
	boundaryPolicyFilePath := fmt.Sprintf("%s/%s", t.TempDir(), "boundary-controller-policy.hcl")
	f, err := os.Create(boundaryPolicyFilePath)
	require.NoError(t, err)
	_, err = f.WriteString(string(data))
	require.NoError(t, err)

	boundaryPolicyName = WritePolicy(t, context.Background(), boundaryPolicyFilePath)

	// Create kv policy
	kvPolicyFilePath = fmt.Sprintf("%s/%s", t.TempDir(), "kv-policy.hcl")
	_, err = os.Create(kvPolicyFilePath)
	require.NoError(t, err)

	return
}

// CreateKvPrivateKeyCredential creates a private key credential in vault and creates a vault policy
// to be able to read that credential. Returns the name of the policy.
func CreateKvPrivateKeyCredential(t testing.TB, secretPath string, user string, keyPath string, kvPolicyFilePath string) string {
	secretName, err := base62.Random(16)
	require.NoError(t, err)

	// Update policy file
	f, err := os.OpenFile(kvPolicyFilePath, os.O_APPEND|os.O_WRONLY, 0o644)
	require.NoError(t, err)
	_, err = f.WriteString(fmt.Sprintf("path \"%s/data/%s\" { capabilities = [\"read\"] }\n",
		secretPath,
		secretName,
	))
	require.NoError(t, err)

	// Create secret
	output := e2e.RunCommand(context.Background(), "vault",
		e2e.WithArgs(
			"kv", "put",
			"-mount", secretPath,
			secretName,
			"username="+user,
			"private_key=@"+keyPath,
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	return secretName
}

// CreateKvPasswordCredential creates a username/password credential in vault and creates a vault
// policy to be able to read that credential. Returns the name of the policy
func CreateKvPasswordCredential(t testing.TB, secretPath string, user string, kvPolicyFilePath string) (secretName string, password string) {
	secretName, err := base62.Random(16)
	require.NoError(t, err)

	// Update policy file
	f, err := os.OpenFile(kvPolicyFilePath, os.O_APPEND|os.O_WRONLY, 0o644)
	require.NoError(t, err)
	_, err = f.WriteString(fmt.Sprintf("path \"%s/data/%s\" { capabilities = [\"read\"] }\n",
		secretPath,
		secretName,
	))
	require.NoError(t, err)

	// Create secret
	password, err = base62.Random(16)
	require.NoError(t, err)
	output := e2e.RunCommand(context.Background(), "vault",
		e2e.WithArgs(
			"kv", "put",
			"-mount", secretPath,
			secretName,
			"username="+user,
			"password="+password,
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	return
}

// WritePolicy adds a policy to vault. Provide a name for the policy that you want to create as well
// as the path to the file that contains the policy definition. Returns a policy name
func WritePolicy(t testing.TB, ctx context.Context, policyFilePath string) string {
	policyName, err := base62.Random(16)
	require.NoError(t, err)

	output := e2e.RunCommand(ctx, "vault",
		e2e.WithArgs("policy", "write", policyName, policyFilePath),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	t.Cleanup(func() {
		output := e2e.RunCommand(ctx, "vault",
			e2e.WithArgs("policy", "delete", policyName),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})

	return policyName
}
