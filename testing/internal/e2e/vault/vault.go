// Package vault provides methods for commonly used vault actions that are used in end-to-end tests.
package vault

import (
	"fmt"
	"os"
	"path"
	"runtime"
	"testing"

	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/kelseyhightower/envconfig"
	"github.com/stretchr/testify/require"
)

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
func Setup(t testing.TB) (string, string) {
	c, err := loadConfig()
	require.NoError(t, err)

	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok)
	policyName := "boundary-controller"
	output := e2e.RunCommand("vault", "policy", "write", policyName,
		path.Join(path.Dir(filename), "boundary-controller-policy.hcl"),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	t.Cleanup(func() {
		output := e2e.RunCommand("vault", "policy", "delete", policyName)
		require.NoError(t, output.Err, string(output.Stderr))
	})

	return c.VaultAddr, policyName
}

// CreateKvPrivateKeyCredential creates a private key credential in vault and creates a vault policy
// to be able to read that credential. Returns the name of the policy.
func CreateKvPrivateKeyCredential(t testing.TB, secretName string, secretPath string, user string, keyPath string) string {
	// Create policy file to read secret
	kvPolicyFileName := "kv-policy-test.hcl"
	kvPolicyFilePath := fmt.Sprintf("%s/%s", t.TempDir(), kvPolicyFileName)

	f, err := os.Create(kvPolicyFilePath)
	require.NoError(t, err)
	_, err = f.WriteString(fmt.Sprintf("path \"%s/data/%s\" { capabilities = [\"read\"] }",
		secretPath,
		secretName,
	))
	require.NoError(t, err)

	// Add policy to vault
	policyName := "kv-read"
	output := e2e.RunCommand("vault", "policy", "write", policyName, kvPolicyFilePath)
	require.NoError(t, output.Err, string(output.Stderr))
	t.Cleanup(func() {
		output := e2e.RunCommand("vault", "policy", "delete", policyName)
		require.NoError(t, output.Err, string(output.Stderr))
	})

	// Create secret
	output = e2e.RunCommand("vault", "kv", "put",
		"-mount", secretPath,
		secretName,
		"username="+user,
		"private_key=@"+keyPath,
	)
	require.NoError(t, output.Err, string(output.Stderr))

	return policyName
}
