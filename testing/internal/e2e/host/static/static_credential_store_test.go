package static_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/boundary/api/credentials"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/require"
)

// TestStaticCredentialStoreCli validates various credential-store operations using the cli
func TestStaticCredentialStoreCli(t *testing.T) {
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
