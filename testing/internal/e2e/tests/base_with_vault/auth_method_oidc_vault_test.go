// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package base_with_vault_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/api/accounts"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/api/managedgroups"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/hashicorp/boundary/testing/internal/e2e/vault"
	"github.com/stretchr/testify/require"
)

// TestAuthMethodOidcVault validates the creation and usage of an OIDC auth
// method. This test uses Vault as the OIDC provider.
func TestAuthMethodOidcVault(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
	require.NoError(t, err)

	ctx := t.Context()

	t.Log("Setting up Vault OIDC provider...")
	// Configure vault authentication: Enable the userpass auth method at the
	// default path
	output := e2e.RunCommand(ctx, "vault", e2e.WithArgs("auth", "enable", "userpass"))
	require.NoError(t, output.Err, string(output.Stderr))
	t.Cleanup(func() {
		ctx := context.Background()
		output := e2e.RunCommand(ctx, "vault", e2e.WithArgs("auth", "disable", "userpass"))
		require.NoError(t, output.Err, string(output.Stderr))
	})

	// Configure vault authentication: Create a policy granting the user read capabilities on the authorization endpoint
	authPolicyPath := fmt.Sprintf("%s/%s", t.TempDir(), "auth-policy.hcl")
	_, err = os.Create(authPolicyPath)
	require.NoError(t, err)
	authPolicyFile, err := os.OpenFile(authPolicyPath, os.O_APPEND|os.O_WRONLY, 0o644)
	require.NoError(t, err)
	_, err = fmt.Fprintf(authPolicyFile,
		"path \"identity/oidc/provider/my-provider/authorize\" { capabilities = [ \"read\" ] }\n",
	)
	require.NoError(t, err)
	require.NoError(t, err)
	authPolicyName := vault.WritePolicy(t, ctx, authPolicyPath)
	t.Cleanup(func() {
		ctx := context.Background()
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
	userEmail := "vault@hashicorp.com"
	userPhone := "123-456-7890"
	output = e2e.RunCommand(ctx, "vault",
		e2e.WithArgs(
			"write",
			"identity/entity",
			fmt.Sprintf("name=%s", userName),
			fmt.Sprintf(`metadata=email=%s`, userEmail),
			fmt.Sprintf(`metadata=phone_number=%s`, userPhone),
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
			fmt.Sprintf(`group_ids=%q`, groupId),
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
	redirect_uri := fmt.Sprintf("%s/v1/auth-methods/oidc:authenticate:callback", boundary.GetAddr(t))
	output = e2e.RunCommand(ctx, "vault",
		e2e.WithArgs(
			"write",
			fmt.Sprintf("identity/oidc/client/%s", oidcClientName),
			fmt.Sprintf("redirect_uris=%s", redirect_uri),
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
		"email": {{identity.entity.metadata.email}},
		"phone_number": {{identity.entity.metadata.phone_number}}
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
			"-api-url-prefix", boundary.GetAddr(t),
			"-claims-scopes", "groups",
			"-claims-scopes", "user",
			"-account-claim-maps", "username=name",
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

	// Set new auth method as primary auth method for the new org
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"scopes", "update",
			"-id", orgId,
			"-primary-auth-method-id", authMethodId,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var updateScopeResult scopes.ScopeUpdateResult
	err = json.Unmarshal(output.Stdout, &updateScopeResult)
	require.NoError(t, err)
	require.Equal(t, authMethodId, updateScopeResult.Item.PrimaryAuthMethodId)

	// Create managed group
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"managed-groups", "create", "oidc",
			"-auth-method-id", authMethodId,
			"-name", groupName,
			"-filter", fmt.Sprintf(`%q in "/userinfo/groups"`, groupName),
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var managedGroupCreateResult managedgroups.ManagedGroupCreateResult
	err = json.Unmarshal(output.Stdout, &managedGroupCreateResult)
	require.NoError(t, err)
	managedGroupId := managedGroupCreateResult.Item.Id
	t.Logf("Created Managed Group: %s", managedGroupId)

	// Start OIDC authentication process to Boundary
	t.Log("Authenticating using OIDC...")
	res, err := http.Post(
		fmt.Sprintf("%s/v1/auth-methods/%s:authenticate", boundary.GetAddr(t), authMethodId),
		"application/json",
		strings.NewReader(`{"command": "start"}`),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		res.Body.Close()
	})
	require.Equal(t, http.StatusOK, res.StatusCode)
	var authResult authmethods.AuthenticateResult
	err = json.NewDecoder(res.Body).Decode(&authResult)
	require.NoError(t, err)
	oidcTokenId := authResult.Attributes["token_id"].(string)
	authUrl := authResult.Attributes["auth_url"].(string)
	u, err := url.Parse(authUrl)
	require.NoError(t, err)
	m, _ := url.ParseQuery(u.RawQuery)
	nonce := m["nonce"][0]
	state := m["state"][0]

	// Vault: Authenticate to get a client token
	res, err = http.Post(
		fmt.Sprintf("%s/v1/auth/userpass/login/%s", c.VaultAddr, userName),
		"application/json",
		strings.NewReader(
			fmt.Sprintf(`{"password": %q}`, userPassword),
		),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		res.Body.Close()
	})
	require.Equal(t, http.StatusOK, res.StatusCode)
	type vaultLoginResponse struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		}
	}
	var loginResponse vaultLoginResponse
	err = json.NewDecoder(res.Body).Decode(&loginResponse)
	require.NoError(t, err)
	vaultClientToken := loginResponse.Auth.ClientToken

	// Vault: authorize oidc request
	req, err := http.NewRequest(
		http.MethodGet,
		fmt.Sprintf(
			"%s/v1/identity/oidc/provider/%s/authorize?scope=%s&response_type=%s&client_id=%s&redirect_uri=%s&state=%s&nonce=%s&max_age=20",
			c.VaultAddr,
			providerName,
			"openid+groups+user",
			"code",
			clientId,
			redirect_uri,
			state,
			nonce,
		),
		nil,
	)
	require.NoError(t, err)
	req.Header.Set("X-Vault-Token", vaultClientToken)
	res, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() {
		res.Body.Close()
	})
	require.Equal(t, http.StatusOK, res.StatusCode)
	type oidcAuthorizeResponse struct {
		Code string `json:"code"`
	}
	var authorizeResponse oidcAuthorizeResponse
	err = json.NewDecoder(res.Body).Decode(&authorizeResponse)
	require.NoError(t, err)
	oidcAuthorizationCode := authorizeResponse.Code

	// Boundary: send a request to the callback URL
	req, err = http.NewRequest(
		http.MethodGet,
		fmt.Sprintf(
			"%s?code=%s&state=%s",
			redirect_uri,
			oidcAuthorizationCode,
			state,
		),
		nil,
	)
	require.NoError(t, err)
	res, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() {
		res.Body.Close()
	})
	require.Equal(t, http.StatusOK, res.StatusCode)

	// Boundary: retrieve the boundary auth token after a successful OIDC login
	res, err = http.Post(
		fmt.Sprintf("%s/v1/auth-methods/%s:authenticate", boundary.GetAddr(t), authMethodId),
		"application/json",
		strings.NewReader(
			fmt.Sprintf(`{"command":"token", "attributes":{"token_id":%q}}`, oidcTokenId),
		),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		res.Body.Close()
	})
	err = json.NewDecoder(res.Body).Decode(&authResult)
	require.NoError(t, err)
	require.Contains(t, authResult.Attributes, "token")
	boundaryToken := authResult.Attributes["token"].(string)

	// Try using the Boundary token to list scopes and users
	t.Log("Using Boundary token...")
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"scopes",
			"list",
			"-token", "env://OIDC_USER_TOKEN",
			"-format", "json",
		),
		e2e.WithEnv("OIDC_USER_TOKEN", boundaryToken),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"users",
			"list",
			"-token", "env://OIDC_USER_TOKEN",
			"-format", "json",
		),
		e2e.WithEnv("OIDC_USER_TOKEN", boundaryToken),
	)
	require.Error(t, output.Err, string(output.Stderr))
	var response boundary.CliError
	err = json.Unmarshal(output.Stderr, &response)
	require.NoError(t, err)
	// User does not have permissions to list users
	require.Equal(t, 403, response.Status)

	// Do a user list without the token (using the admin login). Confirm that
	// this operation works
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"users",
			"list",
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Validate account attributes
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"accounts",
			"list",
			"-auth-method-id", authMethodId,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var accountListResult accounts.AccountListResult
	err = json.Unmarshal(output.Stdout, &accountListResult)
	require.NoError(t, err)
	require.Len(t, accountListResult.Items, 1)
	accountId := accountListResult.Items[0].Id

	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"accounts",
			"read",
			"-id", accountId,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var accountReadResult accounts.AccountReadResult
	err = json.Unmarshal(output.Stdout, &accountReadResult)
	require.NoError(t, err)
	require.Contains(t, accountReadResult.Item.Attributes, "email")
	require.Equal(t, userEmail, accountReadResult.Item.Attributes["email"])
	// This field is set by the -account-claim-maps flag from above
	require.Contains(t, accountReadResult.Item.Attributes, "full_name")
	require.Equal(t, userName, accountReadResult.Item.Attributes["full_name"])

	userInfoClaims, ok := accountReadResult.Item.Attributes["userinfo_claims"].(map[string]any)
	require.True(t, ok, "userinfo_claims is not a map")
	require.Contains(t, userInfoClaims, "email")
	require.Equal(t, userEmail, userInfoClaims["email"])
	require.Contains(t, userInfoClaims, "phone_number")
	require.Equal(t, userPhone, userInfoClaims["phone_number"])
	require.Contains(t, userInfoClaims, "username")
	require.Equal(t, userName, userInfoClaims["username"])
	require.Contains(t, userInfoClaims["groups"], groupName)

	tokenClaims, ok := accountReadResult.Item.Attributes["token_claims"].(map[string]any)
	require.True(t, ok, "token_claims is not a map")
	require.Contains(t, tokenClaims, "email")
	require.Equal(t, userEmail, tokenClaims["email"])
	require.Contains(t, tokenClaims, "phone_number")
	require.Equal(t, userPhone, tokenClaims["phone_number"])
	require.Contains(t, tokenClaims, "username")
	require.Equal(t, userName, tokenClaims["username"])
	require.Contains(t, tokenClaims["groups"], groupName)

	// Verify managed group details
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"managed-groups", "read",
			"-id", managedGroupId,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var managedGroupReadResult managedgroups.ManagedGroupReadResult
	err = json.Unmarshal(output.Stdout, &managedGroupReadResult)
	require.NoError(t, err)
	require.Contains(t, managedGroupReadResult.Item.MemberIds, accountId)
}
