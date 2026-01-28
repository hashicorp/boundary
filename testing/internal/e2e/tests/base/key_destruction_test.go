// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package base_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCliKeyDestruction uses the boundary CLI to test key destruction.
func TestCliKeyDestruction(t *testing.T) {
	e2e.MaybeSkipTest(t)

	ctx := t.Context()
	boundary.AuthenticateAdminCli(t, ctx)

	t.Log("Creating scope...")
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"scopes", "create",
			"-name", "testscope",
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var scopeReply scopes.ScopeCreateResult
	require.NoError(t, json.Unmarshal(output.Stdout, &scopeReply))
	t.Cleanup(func() {
		ctx := context.Background()
		output = e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs(
				"scopes", "delete",
				"-id", scopeReply.Item.Id,
				"-format", "json",
			),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})

	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"scopes", "list-keys",
			"-scope-id", scopeReply.Item.Id,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var keys scopes.KeyListResult
	err := json.Unmarshal(output.Stdout, &keys)
	require.NoError(t, err)
	// We expect to see all DEKs and the root key, so DEKs+1 in total.
	assert.Len(t, keys.Items, len(kms.ValidDekPurposes())+1, "Expected %d keys to be listed, but found %d. Keys: %v", len(kms.ValidDekPurposes())+1, len(keys.Items), keys.Items)
	for _, key := range keys.Items {
		assert.Len(t, key.Versions, 1)
	}

	// Create OIDC auth method to create some encrypted data in the scope
	t.Log("Creating auth method...")
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"auth-methods", "create", "oidc",
			"-scope-id", scopeReply.Item.Id,
			"-api-url-prefix", "http://example.com",
			"-client-id", "something",
			"-client-secret", "somethingelse",
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var amReply authmethods.AuthMethodCreateResult
	require.NoError(t, json.Unmarshal(output.Stdout, &amReply))
	t.Cleanup(func() {
		ctx := context.Background()
		output = e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs(
				"auth-methods", "delete",
				"-id", amReply.Item.Id,
			),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})

	t.Log("Rotating keys...")
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"scopes", "rotate-keys",
			"-scope-id", scopeReply.Item.Id,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"scopes", "list-keys",
			"-scope-id", scopeReply.Item.Id,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	err = json.Unmarshal(output.Stdout, &keys)
	require.NoError(t, err)
	// We expect to see all DEKs and the root key, so DEKs+1 in total.
	assert.Len(t, keys.Items, len(kms.ValidDekPurposes())+1, "Expected %d keys to be listed, but found %d. Keys: %v", len(kms.ValidDekPurposes())+1, len(keys.Items), keys.Items)
	var rootKeyVersionToDestroy *scopes.KeyVersion
	var databaseKeyVersionToDestroy *scopes.KeyVersion
	for _, key := range keys.Items {
		// Each key should have a new version after rotation
		assert.Len(t, key.Versions, 2)
		if key.Purpose == "rootKey" {
			rootKeyVersionToDestroy = key.Versions[1] // Key versions are ordered by version, descending
		}
		if key.Purpose == "database" {
			databaseKeyVersionToDestroy = key.Versions[1]
		}
	}

	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"scopes", "list-key-version-destruction-jobs",
			"-scope-id", scopeReply.Item.Id,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var jobs scopes.KeyVersionDestructionJobListResult
	err = json.Unmarshal(output.Stdout, &jobs)
	require.NoError(t, err)
	assert.Len(t, jobs.Items, 0)

	t.Log("Destroying root key...")
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"scopes", "destroy-key-version",
			"-scope-id", scopeReply.Item.Id,
			"-key-version-id", rootKeyVersionToDestroy.Id,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var destruction struct {
		Item *scopes.KeyVersionDestructionResult
	}
	err = json.Unmarshal(output.Stdout, &destruction)
	require.NoError(t, err)
	// Root key versions should be destroyed synchronously, as they don't require any re-encryption
	assert.Equal(t, "completed", destruction.Item.State)

	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"scopes", "list-key-version-destruction-jobs",
			"-scope-id", scopeReply.Item.Id,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	err = json.Unmarshal(output.Stdout, &jobs)
	require.NoError(t, err)
	assert.Len(t, jobs.Items, 0)

	t.Log("Destroying database key...")
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"scopes", "destroy-key-version",
			"-scope-id", scopeReply.Item.Id,
			"-key-version-id", databaseKeyVersionToDestroy.Id,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	err = json.Unmarshal(output.Stdout, &destruction)
	require.NoError(t, err)
	// Most data key versions should be destroyed asynchronously, as they require re-encryption
	// of existing data.
	assert.Equal(t, "pending", destruction.Item.State)

	// The default scheduler job run interval is 1 minute. The runs become available 1
	// second after the last successful run. We need to re-encrypt data in 1 table,
	// and then remove the key. This job should take between 1 and 2 minutes to run,
	// depending on the timing of the first started run.
	cancelCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	t.Cleanup(cancel)
	for {
		output = e2e.RunCommand(cancelCtx, "boundary",
			e2e.WithArgs(
				"scopes", "list-key-version-destruction-jobs",
				"-scope-id", scopeReply.Item.Id,
				"-format", "json",
			),
		)
		require.NoError(t, output.Err, string(output.Stderr))
		err = json.Unmarshal(output.Stdout, &jobs)
		require.NoError(t, err)
		if len(jobs.Items) == 0 {
			break
		}
		require.Len(t, jobs.Items, 1)
		assert.Equal(t, databaseKeyVersionToDestroy.Id, jobs.Items[0].KeyVersionId)
		select {
		case <-time.After(5 * time.Second):
		case <-cancelCtx.Done():
			t.Fatal("Test timed out waiting for destruction to finish")
		}
	}

	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"scopes", "list-keys",
			"-scope-id", scopeReply.Item.Id,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	err = json.Unmarshal(output.Stdout, &keys)
	require.NoError(t, err)
	// We expect to see all DEKs and the root key, so DEKs+1 in total.
	assert.Len(t, keys.Items, len(kms.ValidDekPurposes())+1, "Expected %d keys to be listed, but found %d. Keys: %v", len(kms.ValidDekPurposes())+1, len(keys.Items), keys.Items)
	for _, key := range keys.Items {
		switch key.Purpose {
		case "rootKey", "database":
			assert.Len(t, key.Versions, 1)
		default:
			assert.Len(t, key.Versions, 2)
		}
	}

	t.Log("Successfully destroyed a root key and data key")
}

// TestApiKeyDestruction uses the boundary Go api to test key destruction.
func TestApiKeyDestruction(t *testing.T) {
	e2e.MaybeSkipTest(t)

	client, err := boundary.NewApiClient()
	require.NoError(t, err)

	ctx := t.Context()
	sc := scopes.NewClient(client)

	t.Log("Creating scope...")
	scope, err := sc.Create(ctx, "global", scopes.WithName("testscope"))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := sc.Delete(context.Background(), scope.Item.Id)
		require.NoError(t, err)
	})

	keys, err := sc.ListKeys(ctx, scope.Item.Id)
	require.NoError(t, err)
	// We expect to see all DEKs and the root key, so DEKs+1 in total.
	assert.Len(t, keys.Items, len(kms.ValidDekPurposes())+1, "Expected %d keys to be listed, but found %d. Keys: %v", len(kms.ValidDekPurposes())+1, len(keys.Items), keys.Items)
	// Assert that all keys have the same number of versions
	for _, key := range keys.Items {
		assert.Len(t, key.Versions, 1)
	}

	// Create OIDC auth method to create some encrypted data in the scope
	t.Log("Creating auth method...")
	amc := authmethods.NewClient(client)
	am, err := amc.Create(ctx, "oidc", scope.Item.Id,
		authmethods.WithOidcAuthMethodApiUrlPrefix("http://example.com"),
		authmethods.WithOidcAuthMethodClientId("something"),
		authmethods.WithOidcAuthMethodClientSecret("somethingelse"),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := amc.Delete(context.Background(), am.Item.Id)
		require.NoError(t, err)
	})

	t.Log("Rotating keys...")
	_, err = sc.RotateKeys(ctx, scope.Item.Id, false)
	require.NoError(t, err)

	keys, err = sc.ListKeys(ctx, scope.Item.Id)
	require.NoError(t, err)
	// We expect to see all DEKs and the root key, so DEKs+1 in total.
	assert.Len(t, keys.Items, len(kms.ValidDekPurposes())+1, "Expected %d keys to be listed, but found %d. Keys: %v", len(kms.ValidDekPurposes())+1, len(keys.Items), keys.Items)
	// Assert that all keys have the same number of versions,
	// one higher than before
	var rootKeyVersionToDestroy *scopes.KeyVersion
	var databaseKeyVersionToDestroy *scopes.KeyVersion
	for _, key := range keys.Items {
		// Each key should have a new version after rotation
		assert.Len(t, key.Versions, 2)
		if key.Purpose == "rootKey" {
			// Key versions are ordered by version, descending.
			// Pick the second newest version.
			rootKeyVersionToDestroy = key.Versions[1]
		}
		if key.Purpose == "database" {
			databaseKeyVersionToDestroy = key.Versions[1]
		}
	}

	jobs, err := sc.ListKeyVersionDestructionJobs(ctx, scope.Item.Id)
	require.NoError(t, err)
	assert.Len(t, jobs.Items, 0)

	t.Log("Destroying root key...")
	result, err := sc.DestroyKeyVersion(ctx, scope.Item.Id, rootKeyVersionToDestroy.Id)
	require.NoError(t, err)
	assert.Equal(t, "completed", result.State)

	jobs, err = sc.ListKeyVersionDestructionJobs(ctx, scope.Item.Id)
	require.NoError(t, err)
	assert.Len(t, jobs.Items, 0)

	t.Log("Destroying database key...")
	result, err = sc.DestroyKeyVersion(ctx, scope.Item.Id, databaseKeyVersionToDestroy.Id)
	require.NoError(t, err)
	assert.Equal(t, "pending", result.State)

	jobs, err = sc.ListKeyVersionDestructionJobs(ctx, scope.Item.Id)
	require.NoError(t, err)
	assert.Len(t, jobs.Items, 1)

	// The default scheduler job run interval is 1 minute. The runs become available 1
	// second after the last successful run. We need to re-encrypt data in 1 table,
	// and then remove the key. This job should take between 1 and 2 minutes to run,
	// depending on the timing of the first started run.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	for {
		jobs, err = sc.ListKeyVersionDestructionJobs(ctx, scope.Item.Id)
		require.NoError(t, err)
		if len(jobs.Items) == 0 {
			break
		}
		require.Len(t, jobs.Items, 1)
		assert.Equal(t, databaseKeyVersionToDestroy.Id, jobs.Items[0].KeyVersionId)
		select {
		case <-time.After(5 * time.Second):
		case <-ctx.Done():
			t.Fatal("Test timed out waiting for destruction to finish")
		}
	}

	keys, err = sc.ListKeys(ctx, scope.Item.Id)
	require.NoError(t, err)
	// We expect to see all DEKs and the root key, so DEKs+1 in total.
	assert.Len(t, keys.Items, len(kms.ValidDekPurposes())+1, "Expected %d keys to be listed, but found %d. Keys: %v", len(kms.ValidDekPurposes())+1, len(keys.Items), keys.Items)
	for _, key := range keys.Items {
		switch key.Purpose {
		case "rootKey", "database":
			assert.Len(t, key.Versions, 1)
		default:
			assert.Len(t, key.Versions, 2)
		}
	}

	t.Log("Successfully destroyed a root key and data key")
}
