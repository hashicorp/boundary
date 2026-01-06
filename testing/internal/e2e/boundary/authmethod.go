// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package boundary

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/go-secure-stdlib/base62"
)

// CreateAuthMethodApi creates a new password auth method using the Go api.
// Returns the id of the new auth method
func CreateAuthMethodApi(t testing.TB, ctx context.Context, client *api.Client, scopeId string) (string, error) {
	name, err := base62.Random(16)
	if err != nil {
		return "", err
	}

	aClient := authmethods.NewClient(client)
	createAuthMethodResult, err := aClient.Create(
		ctx,
		"password",
		scopeId,
		authmethods.WithName(fmt.Sprintf("e2e Auth Method %s", name)))
	if err != nil {
		return "", err
	}

	authMethodId := createAuthMethodResult.Item.Id
	t.Logf("Created Auth Method: %s", authMethodId)
	return authMethodId, nil
}

// CreateOidcAuthMethodApi creates a new oidc auth method using the Go api.
// Returns the id of the new auth method
func CreateOidcAuthMethodApi(t testing.TB, ctx context.Context, client *api.Client, scopeId string) (string, error) {
	name, err := base62.Random(16)
	if err != nil {
		return "", err
	}

	aClient := authmethods.NewClient(client)
	newAMResult, err := aClient.Create(ctx, "oidc", scopeId,
		authmethods.WithOidcAuthMethodApiUrlPrefix("https://some_url_prefix"),
		authmethods.WithOidcAuthMethodClientId("some_client_id"),
		authmethods.WithOidcAuthMethodClientSecret("some_client_secret"),
		authmethods.WithName(fmt.Sprintf("e2e Auth Method %s", name)),
	)
	if err != nil {
		return "", err
	}

	authMethodId := newAMResult.Item.Id
	t.Logf("Created Auth Method: %s", authMethodId)
	return authMethodId, nil
}
