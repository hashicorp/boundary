// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_with_vault_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/hashicorp/boundary/testing/internal/e2e/vault"
	"github.com/stretchr/testify/require"
)

func TestAuthMethodOidcVault(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
	require.NoError(t, err)

	ctx := context.Background()

	t.Log("Setting up Vault OIDC provider...")
	// Configure vault authentication: Enable the userpass auth method at the
	// default path
	output := e2e.RunCommand(ctx, "vault", e2e.WithArgs("auth", "enable", "userpass"))
	require.NoError(t, output.Err, string(output.Stderr))
	t.Cleanup(func() {
		output := e2e.RunCommand(ctx, "vault", e2e.WithArgs("auth", "disable", "userpass"))
		require.NoError(t, output.Err, string(output.Stderr))
	})

	// Configure vault authentication: Create a policy granting the user read capabilities on the authorization endpoint
	authPolicyPath := fmt.Sprintf("%s/%s", t.TempDir(), "auth-policy.hcl")
	_, err = os.Create(authPolicyPath)
	require.NoError(t, err)
	authPolicyFile, err := os.OpenFile(authPolicyPath, os.O_APPEND|os.O_WRONLY, 0o644)
	require.NoError(t, err)
	_, err = authPolicyFile.WriteString(fmt.Sprintf(
		`path "identity/oidc/provider/my-provider/authorize" { capabilities = [ "read" ] }%s`,
		"\n",
	))
	require.NoError(t, err)
	authPolicyName := vault.WritePolicy(t, ctx, authPolicyPath)
	t.Cleanup(func() {
		output := e2e.RunCommand(ctx, "vault",
			e2e.WithArgs("policy", "delete", authPolicyName),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})

	// Configuration vault authentication: Create a user with the auth policy
	userName := "end-user"
	userPassword := "password"
	output = e2e.RunCommand(ctx, "vault",
		e2e.WithArgs(
			"write",
			fmt.Sprintf("auth/userpass/users/%s", userName),
			fmt.Sprintf("password=%s", userPassword),
			fmt.Sprintf("token_policies=%s", authPolicyName),
			"token_ttl=1h",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Create an identity entity
	output = e2e.RunCommand(ctx, "vault",
		e2e.WithArgs(
			"write",
			"identity/entity",
			fmt.Sprintf("name=%s", userName),
			`metadata=email=vault@hashicorp.com`,
			`metadata=phone_number=123-456-7890`,
			"disabled=false",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	output = e2e.RunCommand(ctx, "vault",
		e2e.WithArgs(
			"read",
			"-field=id",
			fmt.Sprintf("identity/entity/name/%s", userName),
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	entityId := strings.TrimSpace(string(output.Stdout))

	// Create an identity group
	groupName := "engineering"
	output = e2e.RunCommand(ctx, "vault",
		e2e.WithArgs(
			"write",
			"identity/group",
			fmt.Sprintf("name=%s", groupName),
			fmt.Sprintf(`member_entity_ids=%s`, entityId),
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	output = e2e.RunCommand(ctx, "vault",
		e2e.WithArgs(
			"read",
			"-field=id",
			fmt.Sprintf("identity/group/name/%s", groupName),
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	groupId := strings.TrimSpace(string(output.Stdout))

	// Get accessor value of the userpass authentication method.
	output = e2e.RunCommand(ctx, "vault",
		e2e.WithArgs(
			"auth",
			"list",
			"-detailed",
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	type AuthListUserPassAttributes struct {
		Accessor string `json:"accessor"`
	}
	type AuthListResponse struct {
		UserPass AuthListUserPassAttributes `json:"userpass/"`
	}
	var authListResult AuthListResponse
	err = json.Unmarshal(output.Stdout, &authListResult)
	require.NoError(t, err)
	userpassAccessor := authListResult.UserPass.Accessor

	// Create an entity alias that maps the end-user entity with the end-user
	// userpass user
	output = e2e.RunCommand(ctx, "vault",
		e2e.WithArgs(
			"write",
			"identity/entity-alias",
			fmt.Sprintf("name=%s", userName),
			fmt.Sprintf(`canonical_id=%s`, entityId),
			fmt.Sprintf(`mount_accessor=%s`, userpassAccessor),
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Create an OIDC assignment, which describes the list of the Vault entities
	// and groups allowed to authenticate with this client.
	assignmentName := "my-assignment"
	output = e2e.RunCommand(ctx, "vault",
		e2e.WithArgs(
			"write",
			fmt.Sprintf("identity/oidc/assignment/%s", assignmentName),
			fmt.Sprintf(`entity_ids=%s`, entityId),
			fmt.Sprintf(`group_ids="%s"`, groupId),
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Create a key
	keyName := "my-key"
	output = e2e.RunCommand(ctx, "vault",
		e2e.WithArgs(
			"write",
			fmt.Sprintf("identity/oidc/key/%s", keyName),
			"allowed_client_ids=*",
			"verification_ttl=2h",
			"rotation_period=1h",
			"algorithm=RS256",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Create an OIDC client
	oidcClientName := "boundary"
	output = e2e.RunCommand(ctx, "vault",
		e2e.WithArgs(
			"write",
			fmt.Sprintf("identity/oidc/client/%s", oidcClientName),
			"redirect_uris=http://127.0.0.1:9200/v1/auth-methods/oidc:authenticate:callback",
			fmt.Sprintf(`assignments=%s`, assignmentName),
			fmt.Sprintf(`key=%s`, keyName),
			"id_token_ttl=30m",
			"access_token_ttl=1h",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	output = e2e.RunCommand(ctx, "vault",
		e2e.WithArgs(
			"read",
			"-field=client_id",
			fmt.Sprintf("identity/oidc/client/%s", oidcClientName),
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	clientId := strings.TrimSpace(string(output.Stdout))

	// Define a Vault OIDC scope for the user
	userScopeTemplate := `{
		"username": {{identity.entity.name}},
		"contact": {
			"email": {{identity.entity.metadata.email}},
			"phone_number": {{identity.entity.metadata.phone_number}}
		}
	}`
	userScopeEncoded := base64.StdEncoding.EncodeToString([]byte(userScopeTemplate))
	output = e2e.RunCommand(ctx, "vault",
		e2e.WithArgs(
			"write",
			"identity/oidc/scope/user",
			`description="The user scope provides claims using Vault identity entity metadata"`,
			fmt.Sprintf(`template=%s`, userScopeEncoded),
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Define a Vault OIDC scope for the group
	groupScopeTemplate := `{
		"groups": {{identity.entity.groups.names}}
	}`
	groupScopeEncoded := base64.StdEncoding.EncodeToString([]byte(groupScopeTemplate))
	output = e2e.RunCommand(ctx, "vault",
		e2e.WithArgs(
			"write",
			"identity/oidc/scope/groups",
			`description="The groups scope provides the groups claim using Vault group membership"`,
			fmt.Sprintf(`template=%s`, groupScopeEncoded),
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Create a Vault OIDC provider
	providerName := "my-provider"
	output = e2e.RunCommand(ctx, "vault",
		e2e.WithArgs(
			"write",
			fmt.Sprintf("identity/oidc/provider/%s", providerName),
			fmt.Sprintf("allowed_client_ids=%s", clientId),
			"scopes_supported=groups,user",
			fmt.Sprintf("issuer=%s", c.VaultAddr),
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Get Issuer URL
	output = e2e.RunCommand(ctx, "curl",
		e2e.WithArgs(
			"-s",
			fmt.Sprintf("%s/v1/identity/oidc/provider/%s/.well-known/openid-configuration", c.VaultAddr, providerName),
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	type oidcConfigResponse struct {
		Issuer string `json:"issuer"`
	}
	var oidcConfig oidcConfigResponse
	err = json.Unmarshal(output.Stdout, &oidcConfig)
	require.NoError(t, err)

	// Get client secret
	output = e2e.RunCommand(ctx, "vault",
		e2e.WithArgs(
			"read",
			"-field=client_secret",
			fmt.Sprintf("identity/oidc/client/%s", oidcClientName),
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	clientSecret := strings.TrimSpace(string(output.Stdout))

	// Create OIDC auth method in Boundary
	boundary.AuthenticateAdminCli(t, ctx)
	orgId, err := boundary.CreateOrgCli(t, ctx)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("scopes", "delete", "-id", orgId))
		require.NoError(t, output.Err, string(output.Stderr))
	})
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"auth-methods", "create", "oidc",
			"-scope-id", orgId,
			"-issuer", oidcConfig.Issuer,
			"-client-id", clientId,
			"-client-secret", clientSecret,
			"-signing-algorithm", "RS256",
			"-api-url-prefix", "http://127.0.0.1:9200",
			"-claims-scopes", "groups",
			"-claims-scopes", "user",
			"-max-age", "20",
			"-name", "e2e Vault OIDC",
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var createAuthMethodResult authmethods.AuthMethodCreateResult
	err = json.Unmarshal(output.Stdout, &createAuthMethodResult)
	require.NoError(t, err)
	authMethodId := createAuthMethodResult.Item.Id
	t.Logf("Created OIDC Auth Method: %s", authMethodId)

	// Set the auth method to active-public
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"auth-methods", "change-state", "oidc",
			"-id", authMethodId,
			"-state", "active-public",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
}
