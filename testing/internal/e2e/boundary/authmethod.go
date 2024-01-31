// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package boundary

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/stretchr/testify/require"
)

// CreateNewAuthMethodApi creates a new password auth method using the Go api.
// Returns the id of the new auth method
func CreateNewAuthMethodApi(t testing.TB, ctx context.Context, client *api.Client, scopeId string) string {
	aClient := authmethods.NewClient(client)
	newAMResult, err := aClient.Create(ctx, "password", scopeId)
	require.NoError(t, err)

	authMethodId := newAMResult.Item.Id
	t.Logf("Created Auth Method: %s", authMethodId)
	return authMethodId
}

// CreateNewOidcAuthMethodApi creates a new oidc auth method using the Go api.
// Returns the id of the new auth method
func CreateNewOidcAuthMethodApi(t testing.TB, ctx context.Context, client *api.Client, scopeId string) string {
	aClient := authmethods.NewClient(client)
	newAMResult, err := aClient.Create(ctx, "oidc", scopeId,
		authmethods.WithOidcAuthMethodApiUrlPrefix("https://some_url_prefix"),
		authmethods.WithOidcAuthMethodClientId("some_client_id"),
		authmethods.WithOidcAuthMethodClientSecret("some_client_secret"),
	)
	require.NoError(t, err)

	authMethodId := newAMResult.Item.Id
	t.Logf("Created Auth Method: %s", authMethodId)
	return authMethodId
}
