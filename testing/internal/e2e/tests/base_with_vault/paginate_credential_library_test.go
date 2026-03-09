// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package base_with_vault_test

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/api/credentiallibraries"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/hashicorp/boundary/testing/internal/e2e/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCliPaginateCredentialLibraries asserts that the CLI automatically paginates to retrieve
// all credential libraries in a single invocation.
func TestCliPaginateCredentialLibraries(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
	require.NoError(t, err)

	ctx := t.Context()
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

	// Configure vault
	boundaryPolicyName := vault.SetupForBoundaryController(t, "testdata/boundary-controller-policy.hcl")
	t.Cleanup(func() {
		ctx := context.Background()
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
		ctx := context.Background()
		output := e2e.RunCommand(ctx, "vault",
			e2e.WithArgs("secrets", "disable", c.VaultSecretPath),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})

	// Create credentials in vault
	privateKeySecretName, privateKeyPolicyName := vault.CreateKvPrivateKeyCredential(t, c.VaultSecretPath, c.TargetSshUser, c.TargetSshKeyPath)
	t.Cleanup(func() {
		ctx := context.Background()
		output := e2e.RunCommand(ctx, "vault",
			e2e.WithArgs("policy", "delete", privateKeyPolicyName),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})

	// Create vault token for boundary
	output = e2e.RunCommand(ctx, "vault",
		e2e.WithArgs(
			"token", "create",
			"-no-default-policy=true",
			"-policy="+boundaryPolicyName,
			"-policy="+privateKeyPolicyName,
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

	// Create a credential store
	storeId, err := boundary.CreateCredentialStoreVaultCli(t, ctx, projectId, c.VaultAddr, credStoreToken)
	require.NoError(t, err)

	// Create enough credential libraries to overflow a single page.
	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	cClient := credentiallibraries.NewClient(client)
	var libraryIds []string
	for i := 0; i < c.MaxPageSize+1; i++ {
		resp, err := cClient.Create(
			ctx, "vault-generic", storeId,
			credentiallibraries.WithVaultCredentialLibraryPath(c.VaultSecretPath+"/data/"+privateKeySecretName),
			credentiallibraries.WithCredentialType("ssh_private_key"),
		)
		require.NoError(t, err)
		libraryIds = append(libraryIds, resp.Item.Id)
	}

	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"credential-libraries", "list",
			"-credential-store-id", storeId,
			"-format=json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var initialCredentialLibraries credentiallibraries.CredentialLibraryListResult
	err = json.Unmarshal(output.Stdout, &initialCredentialLibraries)
	require.NoError(t, err)

	var returnedIds []string
	for _, cred := range initialCredentialLibraries.Items {
		returnedIds = append(returnedIds, cred.Id)
	}

	require.Len(t, initialCredentialLibraries.Items, c.MaxPageSize+1)
	assert.Empty(t, cmp.Diff(returnedIds, libraryIds, cmpopts.SortSlices(func(i, j string) bool { return i < j })))
	assert.Empty(t, initialCredentialLibraries.ResponseType)
	assert.Empty(t, initialCredentialLibraries.RemovedIds)
	assert.Empty(t, initialCredentialLibraries.ListToken)

	resp, err := cClient.Create(
		ctx, "vault-generic", storeId,
		credentiallibraries.WithVaultCredentialLibraryPath(c.VaultSecretPath+"/data/"+privateKeySecretName),
		credentiallibraries.WithCredentialType("ssh_private_key"),
	)
	require.NoError(t, err)
	newCredentialLibraryId := resp.Item.Id
	_, err = cClient.Delete(ctx, initialCredentialLibraries.Items[0].Id)
	require.NoError(t, err)

	// List again, should have the new library but not the deleted library
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"credential-libraries", "list",
			"-credential-store-id", storeId,
			"-format=json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var newCredentialLibraries credentiallibraries.CredentialLibraryListResult
	err = json.Unmarshal(output.Stdout, &newCredentialLibraries)
	require.NoError(t, err)

	require.Len(t, newCredentialLibraries.Items, c.MaxPageSize+1)
	// The first item should be the most recently created, which
	// should be our new credential
	firstItem := newCredentialLibraries.Items[0]
	assert.Equal(t, newCredentialLibraryId, firstItem.Id)
	assert.Empty(t, newCredentialLibraries.ResponseType)
	assert.Empty(t, newCredentialLibraries.RemovedIds)
	assert.Empty(t, newCredentialLibraries.ListToken)
	// Ensure the deleted credential isn't returned
	for _, credential := range newCredentialLibraries.Items {
		assert.NotEqual(t, credential.Id, initialCredentialLibraries.Items[0].Id)
	}
}

// TestApiPaginateCredentialLibraries asserts that the API automatically paginates to retrieve
// all CredentialLibraries in a single invocation.
func TestApiPaginateCredentialLibraries(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
	require.NoError(t, err)

	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	ctx := t.Context()
	sClient := scopes.NewClient(client)
	cClient := credentiallibraries.NewClient(client)
	orgId, err := boundary.CreateOrgApi(t, ctx, client)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		_, err := sClient.Delete(ctx, orgId)
		require.NoError(t, err)
	})
	projectId, err := boundary.CreateProjectApi(t, ctx, client, orgId)
	require.NoError(t, err)

	// Configure vault
	boundaryPolicyName := vault.SetupForBoundaryController(t, "testdata/boundary-controller-policy.hcl")
	t.Cleanup(func() {
		ctx := context.Background()
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
		ctx := context.Background()
		output := e2e.RunCommand(ctx, "vault",
			e2e.WithArgs("secrets", "disable", c.VaultSecretPath),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})

	// Create credentials in vault
	privateKeySecretName, privateKeyPolicyName := vault.CreateKvPrivateKeyCredential(t, c.VaultSecretPath, c.TargetSshUser, c.TargetSshKeyPath)
	t.Cleanup(func() {
		ctx := context.Background()
		output := e2e.RunCommand(ctx, "vault",
			e2e.WithArgs("policy", "delete", privateKeyPolicyName),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})

	// Create vault token for boundary
	output = e2e.RunCommand(ctx, "vault",
		e2e.WithArgs(
			"token", "create",
			"-no-default-policy=true",
			"-policy="+boundaryPolicyName,
			"-policy="+privateKeyPolicyName,
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

	// Create a credential store
	storeId, err := boundary.CreateCredentialStoreVaultApi(t, ctx, client, projectId, c.VaultAddr, credStoreToken)
	require.NoError(t, err)

	// Create enough credential libraries to overflow a single page.
	var libraryIds []string
	for i := 0; i < c.MaxPageSize+1; i++ {
		resp, err := cClient.Create(
			ctx, "vault-generic", storeId,
			credentiallibraries.WithVaultCredentialLibraryPath(c.VaultSecretPath+"/data/"+privateKeySecretName),
			credentiallibraries.WithCredentialType("ssh_private_key"),
		)
		require.NoError(t, err)
		libraryIds = append(libraryIds, resp.Item.Id)
	}

	initialCredentialLibraries, err := cClient.List(ctx, storeId)
	require.NoError(t, err)

	var returnedIds []string
	for _, cred := range initialCredentialLibraries.Items {
		returnedIds = append(returnedIds, cred.Id)
	}

	require.Len(t, initialCredentialLibraries.Items, c.MaxPageSize+1)
	assert.Empty(t, cmp.Diff(returnedIds, libraryIds, cmpopts.SortSlices(func(i, j string) bool { return i < j })))
	assert.Equal(t, "complete", initialCredentialLibraries.ResponseType)
	assert.Empty(t, initialCredentialLibraries.RemovedIds)
	assert.NotEmpty(t, initialCredentialLibraries.ListToken)
	mapItems, ok := initialCredentialLibraries.GetResponse().Map["items"]
	require.True(t, ok)
	mapSliceItems, ok := mapItems.([]any)
	require.True(t, ok)
	assert.Len(t, mapSliceItems, c.MaxPageSize+1)

	// Create a new library and destroy one of the others
	resp, err := cClient.Create(
		ctx, "vault-generic", storeId,
		credentiallibraries.WithVaultCredentialLibraryPath(c.VaultSecretPath+"/data/"+privateKeySecretName),
		credentiallibraries.WithCredentialType("ssh_private_key"),
	)
	require.NoError(t, err)
	newCredentialLibraryId := resp.Item.Id
	_, err = cClient.Delete(ctx, initialCredentialLibraries.Items[0].Id)
	require.NoError(t, err)

	// List again, should have the new and deleted library
	newCredentialLibraries, err := cClient.List(ctx, storeId, credentiallibraries.WithListToken(initialCredentialLibraries.ListToken))
	require.NoError(t, err)

	// Note that this will likely contain all the credential libraries,
	// since they were created very shortly before the listing,
	// and we add a 30 second buffer to the lower bound of update
	// times when listing.
	require.GreaterOrEqual(t, len(newCredentialLibraries.Items), 1)
	// The first item should be the most recently created, which
	// should be our new library
	firstItem := newCredentialLibraries.Items[0]
	assert.Equal(t, newCredentialLibraryId, firstItem.Id)
	assert.Equal(t, "complete", newCredentialLibraries.ResponseType)
	// Note that the removed IDs may contain entries from other tests,
	// so just check that there is at least 1 entry and that our entry
	// is somewhere in the list.
	require.GreaterOrEqual(t, len(newCredentialLibraries.RemovedIds), 1)
	assert.True(t, slices.ContainsFunc(newCredentialLibraries.RemovedIds, func(credentialId string) bool {
		return credentialId == initialCredentialLibraries.Items[0].Id
	}))
	assert.NotEmpty(t, newCredentialLibraries.ListToken)
	// Check that the response map contains all entries
	mapItems, ok = newCredentialLibraries.GetResponse().Map["items"]
	require.True(t, ok)
	mapSliceItems, ok = mapItems.([]any)
	require.True(t, ok)
	assert.GreaterOrEqual(t, len(mapSliceItems), 1)
}
