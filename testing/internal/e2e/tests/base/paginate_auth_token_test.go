// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package base_test

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCliPaginateAuthTokens asserts that the CLI automatically paginates to retrieve
// all auth tokens in a single invocation.
func TestCliPaginateAuthTokens(t *testing.T) {
	e2e.MaybeSkipTest(t)
	t.Skip("Skipping test due to 'large estimated count' bug: ICU-16649")
	c, err := loadTestConfig()
	require.NoError(t, err)

	ctx := t.Context()
	boundary.AuthenticateAdminCli(t, ctx)
	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	orgId, err := boundary.CreateOrgCli(t, ctx)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("scopes", "delete", "-id", orgId))
		require.NoError(t, output.Err, string(output.Stderr))
	})
	userId, err := boundary.CreateUserApi(t, ctx, client, orgId)
	require.NoError(t, err)
	amId, err := boundary.CreateAuthMethodApi(t, ctx, client, orgId)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("auth-methods", "delete", "-id", amId))
		require.NoError(t, output.Err, string(output.Stderr))
	})
	accId, password, err := boundary.CreateAccountCli(t, ctx, amId, "testuser")
	require.NoError(t, err)
	err = boundary.SetAccountToUserCli(t, ctx, userId, accId)
	require.NoError(t, err)

	boundary.AuthenticateCli(t, ctx, amId, "testuser", password)

	// Create enough auth tokens to overflow a single page.
	// We created an auth token when we authenticated, so we
	// need to remove it from the total auth token count.
	numPrecreatedAuthTokens := 1
	var authTokenIds []string
	for i := 0; i < c.MaxPageSize+1-numPrecreatedAuthTokens; i++ {
		authTokenIds = append(authTokenIds, createAuthToken(t, ctx, client, amId, "testuser", password))
	}

	// List auth tokens
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"auth-tokens", "list",
			"-recursive",
			"-format=json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var initialAuthTokens authtokens.AuthTokenListResult
	err = json.Unmarshal(output.Stdout, &initialAuthTokens)
	require.NoError(t, err)

	var returnedIds []string
	// Ignore the precreated auth token, which will appear at the end
	for _, authtoken := range initialAuthTokens.Items[:len(initialAuthTokens.Items)-numPrecreatedAuthTokens] {
		returnedIds = append(returnedIds, authtoken.Id)
	}

	require.Len(t, initialAuthTokens.Items, c.MaxPageSize+1)
	assert.Empty(t, cmp.Diff(returnedIds, authTokenIds, cmpopts.SortSlices(func(i, j string) bool { return i < j })))
	assert.Empty(t, initialAuthTokens.ResponseType)
	assert.Empty(t, initialAuthTokens.RemovedIds)
	assert.Empty(t, initialAuthTokens.ListToken)

	// Create a new auth token and destroy one of the other auth tokens
	newAuthTokenId := createAuthToken(t, ctx, client, amId, "testuser", password)
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"auth-tokens", "delete",
			"-id", initialAuthTokens.Items[0].Id,
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// List again, should have the new auth token but not the deleted auth token
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"auth-tokens", "list",
			"-recursive",
			"-format=json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var newAuthTokens authtokens.AuthTokenListResult
	err = json.Unmarshal(output.Stdout, &newAuthTokens)
	require.NoError(t, err)

	require.Len(t, newAuthTokens.Items, c.MaxPageSize+1)
	// The first item should be the most recently created, which
	// should be our new auth token
	firstItem := newAuthTokens.Items[0]
	assert.Equal(t, newAuthTokenId, firstItem.Id)
	assert.Empty(t, newAuthTokens.ResponseType)
	assert.Empty(t, newAuthTokens.RemovedIds)
	assert.Empty(t, newAuthTokens.ListToken)
	// Ensure the deleted auth token isn't returned
	for _, authtoken := range newAuthTokens.Items {
		assert.NotEqual(t, authtoken.Id, initialAuthTokens.Items[0].Id)
	}
}

// TestApiPaginateAuthTokens asserts that the API automatically paginates to retrieve
// all auth tokens in a single invocation.
func TestApiPaginateAuthTokens(t *testing.T) {
	e2e.MaybeSkipTest(t)
	t.Skip("Skipping test due to 'large estimated count' bug: ICU-16649")
	c, err := loadTestConfig()
	require.NoError(t, err)

	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	adminToken := client.Token()
	ctx := t.Context()
	sClient := scopes.NewClient(client)
	amClient := authmethods.NewClient(client)
	atClient := authtokens.NewClient(client)
	orgId, err := boundary.CreateOrgApi(t, ctx, client)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		client.SetToken(adminToken)
		_, err = sClient.Delete(ctx, orgId)
		require.NoError(t, err)
	})
	userId, err := boundary.CreateUserApi(t, ctx, client, orgId)
	require.NoError(t, err)
	amId, err := boundary.CreateAuthMethodApi(t, ctx, client, orgId)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		client.SetToken(adminToken)
		_, err := amClient.Delete(ctx, amId)
		require.NoError(t, err)
	})
	accId, password, err := boundary.CreateAccountCli(t, ctx, amId, "testuser")
	require.NoError(t, err)
	err = boundary.SetAccountToUserCli(t, ctx, userId, accId)
	require.NoError(t, err)

	// Authenticate as the user
	authenticationResult, err := amClient.Authenticate(ctx, amId, "login",
		map[string]any{
			"login_name": "testuser",
			"password":   password,
		},
	)
	require.NoError(t, err)
	at, err := authenticationResult.GetAuthToken()
	require.NoError(t, err)
	client.SetToken(at.Token)

	// Create enough auth tokens to overflow a single page.
	// Creating an org comes with two automatically created auth tokens,
	// "Login and Default Grants" and "Administration", so we
	// need to remove them from the total auth token count.
	numPrecreatedAuthTokens := 1
	var authtokenIds []string
	for i := 0; i < c.MaxPageSize+1-numPrecreatedAuthTokens; i++ {
		authtokenIds = append(authtokenIds, createAuthToken(t, ctx, client, amId, "testuser", password))
	}

	// List auth tokens
	initialAuthTokens, err := atClient.List(ctx, orgId, authtokens.WithRecursive(true))
	require.NoError(t, err)

	var returnedIds []string
	// Ignore the precreated auth tokens, which will appear at the end
	for _, authtoken := range initialAuthTokens.Items[:len(initialAuthTokens.Items)-numPrecreatedAuthTokens] {
		returnedIds = append(returnedIds, authtoken.Id)
	}

	require.Len(t, initialAuthTokens.Items, c.MaxPageSize+1)
	assert.Empty(t, cmp.Diff(returnedIds, authtokenIds, cmpopts.SortSlices(func(i, j string) bool { return i < j })))
	assert.Equal(t, "complete", initialAuthTokens.ResponseType)
	assert.Empty(t, initialAuthTokens.RemovedIds)
	assert.NotEmpty(t, initialAuthTokens.ListToken)
	mapItems, ok := initialAuthTokens.GetResponse().Map["items"]
	require.True(t, ok)
	mapSliceItems, ok := mapItems.([]any)
	require.True(t, ok)
	assert.Len(t, mapSliceItems, c.MaxPageSize+1)

	// Create a new auth token and destroy one of the other auth tokens
	newAuthTokenId := createAuthToken(t, ctx, client, amId, "testuser", password)
	_, err = atClient.Delete(ctx, initialAuthTokens.Items[0].Id)
	require.NoError(t, err)

	// List again, should have the new and deleted auth token
	newAuthTokens, err := atClient.List(ctx, orgId, authtokens.WithListToken(initialAuthTokens.ListToken), authtokens.WithRecursive(true))
	require.NoError(t, err)

	// Note that this will likely contain all the auth tokens,
	// since they were created very shortly before the listing,
	// and we add a 30 second buffer to the lower bound of update
	// times when listing.
	require.GreaterOrEqual(t, len(newAuthTokens.Items), 1)
	// The first item should be the most recently created, which
	// should be our new auth token
	firstItem := newAuthTokens.Items[0]
	assert.Equal(t, newAuthTokenId, firstItem.Id)
	assert.Equal(t, "complete", newAuthTokens.ResponseType)
	// Note that the removed IDs may contain entries from other tests,
	// so just check that there is at least 1 entry and that our entry
	// is somewhere in the list.
	require.GreaterOrEqual(t, len(newAuthTokens.RemovedIds), 1)
	assert.True(t, slices.ContainsFunc(newAuthTokens.RemovedIds, func(authtokenId string) bool {
		return authtokenId == initialAuthTokens.Items[0].Id
	}))
	assert.NotEmpty(t, newAuthTokens.ListToken)
	// Check that the response map contains all entries
	mapItems, ok = newAuthTokens.GetResponse().Map["items"]
	require.True(t, ok)
	mapSliceItems, ok = mapItems.([]any)
	require.True(t, ok)
	assert.GreaterOrEqual(t, len(mapSliceItems), 1)
}

func createAuthToken(t testing.TB, ctx context.Context, client *api.Client, authMethodId, loginName, password string) string {
	authmethodsClient := authmethods.NewClient(client)
	authenticationResult, err := authmethodsClient.Authenticate(ctx, authMethodId, "login",
		map[string]any{
			"login_name": loginName,
			"password":   password,
		},
	)
	require.NoError(t, err)
	at, err := authenticationResult.GetAuthToken()
	require.NoError(t, err)
	return at.Id
}
