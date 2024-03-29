// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/boundary/api/credentials"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testCredentialsFile = "testdata/credential.json"
	testPemFile         = "testdata/private-key.pem"
	testPassword        = "password"
)

// TestCliStaticCredentialStore validates various credential-store operations using the cli
func TestCliStaticCredentialStore(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
	require.NoError(t, err)

	ctx := context.Background()
	boundary.AuthenticateAdminCli(t, ctx)
	orgId, err := boundary.CreateOrgCli(t, ctx)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("scopes", "delete", "-id", orgId))
		require.NoError(t, output.Err, string(output.Stderr))
	})
	projectId, err := boundary.CreateProjectCli(t, ctx, orgId)
	require.NoError(t, err)
	hostCatalogId, err := boundary.CreateHostCatalogCli(t, ctx, projectId)
	require.NoError(t, err)
	hostSetId, err := boundary.CreateHostSetCli(t, ctx, hostCatalogId)
	require.NoError(t, err)
	hostId, err := boundary.CreateHostCli(t, ctx, hostCatalogId, c.TargetAddress)
	require.NoError(t, err)
	err = boundary.AddHostToHostSetCli(t, ctx, hostSetId, hostId)
	require.NoError(t, err)
	newTargetId := boundary.CreateNewTargetCli(t, ctx, projectId, c.TargetPort)
	boundary.AddHostSourceToTargetCli(t, ctx, newTargetId, hostSetId)

	err = createPrivateKeyPemFile(testPemFile)
	require.NoError(t, err)
	t.Cleanup(func() {
		err := os.Remove(testPemFile)
		require.NoError(t, err)
	})

	// Create static credentials
	newCredentialStoreId := boundary.CreateNewCredentialStoreStaticCli(t, ctx, projectId)
	privateKeyCredentialsId := boundary.CreateNewStaticCredentialPrivateKeyCli(t, ctx, newCredentialStoreId, c.TargetSshUser, testPemFile)
	pwCredentialsId := boundary.CreateNewStaticCredentialPasswordCli(t, ctx, newCredentialStoreId, c.TargetSshUser, testPassword)
	jsonCredentialsId := boundary.CreateNewStaticCredentialJsonCli(t, ctx, newCredentialStoreId, testCredentialsFile)

	// Get credentials for target (expect empty)
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("targets", "authorize-session", "-id", newTargetId, "-format", "json"),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newSessionAuthorizationResult targets.SessionAuthorizationResult
	err = json.Unmarshal(output.Stdout, &newSessionAuthorizationResult)
	require.NoError(t, err)
	require.True(t, newSessionAuthorizationResult.Item.Credentials == nil)

	// Add credentials to target
	boundary.AddBrokeredCredentialSourceToTargetCli(t, ctx, newTargetId, privateKeyCredentialsId)
	boundary.AddBrokeredCredentialSourceToTargetCli(t, ctx, newTargetId, jsonCredentialsId)
	boundary.AddBrokeredCredentialSourceToTargetCli(t, ctx, newTargetId, pwCredentialsId)

	// Get credentials for target
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("targets", "authorize-session", "-id", newTargetId, "-format", "json"),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	err = json.Unmarshal(output.Stdout, &newSessionAuthorizationResult)
	require.NoError(t, err)

	brokeredCredentials := make([]map[string]any, 0, 3)
	for _, credential := range newSessionAuthorizationResult.Item.Credentials {
		brokeredCredentials = append(brokeredCredentials, credential.Credential)
	}

	// Prepare expected credentials
	testCredentialsJson, err := os.ReadFile(testCredentialsFile)
	require.NoError(t, err)
	var expectedJsonCredentials map[string]any
	err = json.Unmarshal(testCredentialsJson, &expectedJsonCredentials)
	require.NoError(t, err)

	sshPrivateKeyFileContent, err := os.ReadFile(testPemFile)
	require.NoError(t, err)
	sshPrivateKey := strings.TrimSpace(string(sshPrivateKeyFileContent))

	expectedCredentials := []map[string]any{
		{"username": c.TargetSshUser, "password": testPassword},
		{"username": c.TargetSshUser, "private_key": sshPrivateKey},
		expectedJsonCredentials,
	}

	assert.ElementsMatch(t, expectedCredentials, brokeredCredentials)

	// Delete credential store
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("credential-stores", "delete", "-id", newCredentialStoreId),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	t.Log("Waiting for credential store to be deleted...")
	err = backoff.RetryNotify(
		func() error {
			output := e2e.RunCommand(ctx, "boundary",
				e2e.WithArgs("credential-stores", "read", "-id", newCredentialStoreId, "-format", "json"),
			)
			if output.Err == nil {
				return fmt.Errorf("Deleted credential can still be read: '%s'", output.Stdout)
			}

			var response boundary.CliError
			err := json.Unmarshal(output.Stderr, &response)
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
	t.Log("Successfully deleted credential store")
}

func createPrivateKeyPemFile(fileName string) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	pemFile, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer pemFile.Close()

	privateKey := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	return pem.Encode(pemFile, privateKey)
}

// TestApiStaticCredentialStore uses the Go api to create a credential using
// boundary's built-in credential store. The test then attaches that credential to a target.
func TestApiStaticCredentialStore(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
	require.NoError(t, err)

	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	ctx := context.Background()

	orgId, err := boundary.CreateOrgApi(t, ctx, client)
	require.NoError(t, err)
	t.Cleanup(func() {
		scopeClient := scopes.NewClient(client)
		_, err := scopeClient.Delete(ctx, orgId)
		require.NoError(t, err)
	})
	projectId, err := boundary.CreateProjectApi(t, ctx, client, orgId)
	require.NoError(t, err)
	hostCatalogId, err := boundary.CreateHostCatalogApi(t, ctx, client, projectId)
	require.NoError(t, err)
	hostSetId, err := boundary.CreateHostSetApi(t, ctx, client, hostCatalogId)
	require.NoError(t, err)
	hostId, err := boundary.CreateHostApi(t, ctx, client, hostCatalogId, c.TargetAddress)
	require.NoError(t, err)
	err = boundary.AddHostToHostSetApi(t, ctx, client, hostSetId, hostId)
	require.NoError(t, err)
	newTargetId := boundary.CreateNewTargetApi(t, ctx, client, projectId, c.TargetPort)
	boundary.AddHostSourceToTargetApi(t, ctx, client, newTargetId, hostSetId)
	newCredentialStoreId := boundary.CreateNewCredentialStoreStaticApi(t, ctx, client, projectId)

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
	retrievedUser, ok := newSessionAuthorization.Credentials[0].Credential["username"].(string)
	require.True(t, ok)
	retrievedKey, ok := newSessionAuthorization.Credentials[0].Credential["private_key"].(string)
	require.True(t, ok)
	assert.Equal(t, c.TargetSshUser, retrievedUser)
	require.Equal(t, string(k), retrievedKey)
	t.Log("Successfully retrieved credentials for target")
}
