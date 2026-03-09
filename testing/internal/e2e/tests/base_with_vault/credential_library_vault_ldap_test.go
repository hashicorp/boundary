// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package base_with_vault_test

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/hashicorp/boundary/testing/internal/e2e/vault"
	"github.com/stretchr/testify/require"
)

// TestApiVaultLdapCredentialLibrary uses the Boundary API to test CRUDL on a
// Vault LDAP credential library. Additionally, it tests assigning it as a
// brokered credential source on a TCP target and connecting.
func TestApiVaultLdapCredentialLibrary(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
	require.NoError(t, err)
	require.NotNil(t, c)

	client, err := boundary.NewApiClient()
	require.NoError(t, err)
	require.NotNil(t, client)

	orgId, err := boundary.CreateOrgApi(t, t.Context(), client)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := scopes.NewClient(client).Delete(context.Background(), orgId)
		require.NoError(t, err)
	})
	projectId, err := boundary.CreateProjectApi(t, t.Context(), client, orgId)
	require.NoError(t, err)

	// Create TCP target.
	targetPort, err := strconv.ParseUint(c.TargetPort, 10, 32)
	require.NoError(t, err)
	targetId, err := boundary.CreateTargetApi(t, t.Context(), client, projectId, "tcp",
		targets.WithTcpTargetDefaultPort(uint32(targetPort)),
		targets.WithTcpTargetDefaultClientPort(uint32(targetPort)),
	)
	require.NoError(t, err)

	// Create host catalog, host set and host; Add host set to the target as a
	// host source.
	hostCatalogId, err := boundary.CreateHostCatalogApi(t, t.Context(), client, projectId)
	require.NoError(t, err)
	hostSetId, err := boundary.CreateHostSetApi(t, t.Context(), client, hostCatalogId)
	require.NoError(t, err)
	hostId, err := boundary.CreateHostApi(t, t.Context(), client, hostCatalogId, c.TargetAddress)
	require.NoError(t, err)
	err = boundary.AddHostToHostSetApi(t, t.Context(), client, hostSetId, hostId)
	require.NoError(t, err)
	err = boundary.AddHostSourceToTargetApi(t, t.Context(), client, targetId, hostSetId)
	require.NoError(t, err)

	// Configure Vault for LDAP.
	boundaryPolicyName := vault.SetupForBoundaryController(t, "testdata/boundary-controller-policy.hcl")
	t.Cleanup(func() {
		ctx := context.Background()
		output := e2e.RunCommand(ctx, "vault",
			e2e.WithArgs("policy", "delete", boundaryPolicyName),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})

	ldapPolicyName, err := vault.SetupLdapWithOpenLdap(t, c.VaultLdapPath,
		c.LdapAddress, c.LdapAdminDn, c.LdapAdminPassword,
		c.LdapDomainDn, c.LdapUserName, c.LdapGroupName,
	)
	t.Cleanup(func() {
		ctx := context.Background()
		// Destroy LDAP secrets engine and LDAP policy.
		output := e2e.RunCommand(ctx, "vault",
			e2e.WithArgs("secrets", "disable", c.VaultLdapPath),
		)
		require.NoError(t, output.Err, string(output.Stderr))

		output = e2e.RunCommand(ctx, "vault",
			e2e.WithArgs("policy", "delete", ldapPolicyName),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	require.NoError(t, err)

	// Create Vault token for Boundary.
	output := e2e.RunCommand(t.Context(), "vault",
		e2e.WithArgs(
			"token", "create",
			"-no-default-policy=true",
			fmt.Sprintf("-policy=%s", boundaryPolicyName),
			fmt.Sprintf("-policy=%s", ldapPolicyName),
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
	vaultToken := tokenCreateResult.Auth.Client_Token

	// Create two Vault LDAP credential libraries: One with static, one with
	// dynamic creds.
	storeId, err := boundary.CreateCredentialStoreVaultApi(t, t.Context(), client, projectId, c.VaultAddr, vaultToken)
	require.NoError(t, err)
	staticCredVclId, err := boundary.CreateVaultLdapCredentialLibraryApi(t, t.Context(), client, storeId, fmt.Sprintf("%s/static-cred/%s", c.VaultLdapPath, c.LdapUserName))
	require.NoError(t, err)
	dynamicCredVclId, err := boundary.CreateVaultLdapCredentialLibraryApi(t, t.Context(), client, storeId, fmt.Sprintf("%s/creds/%s", c.VaultLdapPath, c.LdapGroupName))
	require.NoError(t, err)
	err = boundary.AddBrokeredCredentialSourceToTargetApi(t, t.Context(), client, targetId, staticCredVclId)
	require.NoError(t, err)
	err = boundary.AddBrokeredCredentialSourceToTargetApi(t, t.Context(), client, targetId, dynamicCredVclId)
	require.NoError(t, err)

	// Authorize session and assert that session credentials exist.
	sar, err := targets.NewClient(client).AuthorizeSession(t.Context(), targetId)
	require.NoError(t, err)
	require.NotNil(t, sar)

	sa, err := sar.GetSessionAuthorization()
	require.NoError(t, err)
	require.NotNil(t, sa)

	require.Len(t, sa.Credentials, 2) // One for static, one for dynamic role.
	slices.SortFunc(sa.Credentials, func(a *targets.SessionCredential, b *targets.SessionCredential) int {
		// Sort by static role credential library first.
		if strings.EqualFold(staticCredVclId, a.CredentialSource.Id) {
			return -1
		}
		return 1
	})

	// Determine the LDAP server's domain using LDAP dn. LdapDomainDn is a
	// string like "dc=subdomain,dc=domain,dc=tld".
	expDomain := strings.ReplaceAll(
		strings.ReplaceAll(c.LdapDomainDn, "dc=", ""), // Transforms into "subdomain,domain,tld".
		",", ".", // Then replace commas with periods to get "subdomain.domain.tld".
	)

	// Static credential.
	require.NotEmpty(t, sa.Credentials[0].Credential)
	require.Contains(t, sa.Credentials[0].Credential, "username")
	require.Contains(t, sa.Credentials[0].Credential, "password")
	require.Contains(t, sa.Credentials[0].Credential, "domain")
	require.EqualValues(t, c.LdapUserName, sa.Credentials[0].Credential["username"])
	require.NotEmpty(t, sa.Credentials[0].Credential["password"])
	require.EqualValues(t, expDomain, sa.Credentials[0].Credential["domain"])

	require.NotNil(t, sa.Credentials[0].CredentialSource)
	require.EqualValues(t, staticCredVclId, sa.Credentials[0].CredentialSource.Id)
	require.Contains(t, sa.Credentials[0].CredentialSource.Name, "e2e vault credential library")
	require.EqualValues(t, "vault-ldap", sa.Credentials[0].CredentialSource.Type)
	require.EqualValues(t, storeId, sa.Credentials[0].CredentialSource.CredentialStoreId)
	require.EqualValues(t, "username_password_domain", sa.Credentials[0].CredentialSource.CredentialType)

	require.NotNil(t, sa.Credentials[0].Secret)
	require.NotEmpty(t, sa.Credentials[0].Secret.Decoded)
	require.Contains(t, sa.Credentials[0].Secret.Decoded, "username")
	require.Contains(t, sa.Credentials[0].Secret.Decoded, "password")
	require.Contains(t, sa.Credentials[0].Secret.Decoded, "dn")
	require.EqualValues(t, c.LdapUserName, sa.Credentials[0].Secret.Decoded["username"])
	require.EqualValues(t, sa.Credentials[0].Credential["password"], sa.Credentials[0].Secret.Decoded["password"])
	require.EqualValues(t, fmt.Sprintf("cn=%s,%s", c.LdapUserName, c.LdapDomainDn), sa.Credentials[0].Secret.Decoded["dn"])

	// Dynamic credential.
	require.NotEmpty(t, sa.Credentials[1].Credential)
	require.Contains(t, sa.Credentials[1].Credential, "username")
	require.Contains(t, sa.Credentials[1].Credential, "password")
	require.Contains(t, sa.Credentials[1].Credential, "domain")
	require.Contains(t, sa.Credentials[1].Credential["username"], fmt.Sprintf("b_token_%s_", c.LdapGroupName))
	require.NotEmpty(t, sa.Credentials[1].Credential["password"])
	require.EqualValues(t, expDomain, sa.Credentials[1].Credential["domain"])

	require.NotNil(t, sa.Credentials[1].CredentialSource)
	require.EqualValues(t, dynamicCredVclId, sa.Credentials[1].CredentialSource.Id)
	require.Contains(t, sa.Credentials[1].CredentialSource.Name, "e2e vault credential library")
	require.EqualValues(t, "vault-ldap", sa.Credentials[1].CredentialSource.Type)
	require.EqualValues(t, storeId, sa.Credentials[1].CredentialSource.CredentialStoreId)
	require.EqualValues(t, "username_password_domain", sa.Credentials[1].CredentialSource.CredentialType)

	require.NotNil(t, sa.Credentials[1].Secret)
	require.NotEmpty(t, sa.Credentials[1].Secret.Decoded)
	require.Contains(t, sa.Credentials[1].Secret.Decoded, "username")
	require.Contains(t, sa.Credentials[1].Secret.Decoded, "password")
	require.Contains(t, sa.Credentials[1].Secret.Decoded, "distinguished_names")
	require.EqualValues(t, sa.Credentials[1].Credential["username"], sa.Credentials[1].Secret.Decoded["username"])
	require.EqualValues(t, sa.Credentials[1].Credential["password"], sa.Credentials[1].Secret.Decoded["password"])
	distinguishedNames, ok := sa.Credentials[1].Secret.Decoded["distinguished_names"].([]any)
	require.True(t, ok)
	require.NotEmpty(t, distinguishedNames)
	require.Contains(t, distinguishedNames, fmt.Sprintf("cn=%s,%s", sa.Credentials[1].Secret.Decoded["username"], c.LdapDomainDn))
	require.Contains(t, distinguishedNames, fmt.Sprintf("cn=%s,%s", c.LdapGroupName, c.LdapDomainDn))
}

// TestCliVaultLdapCredentialLibrary uses the Boundary CLI to test CRUDL on a
// Vault LDAP credential library. Additionally, it tests assigning it as a
// brokered credential source on a TCP target and connecting.
func TestCliVaultLdapCredentialLibrary(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
	require.NoError(t, err)

	boundary.AuthenticateAdminCli(t, t.Context())
	orgId, err := boundary.CreateOrgCli(t, t.Context())
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("scopes", "delete", "-id", orgId))
		require.NoError(t, output.Err, string(output.Stderr))
	})

	projectId, err := boundary.CreateProjectCli(t, t.Context(), orgId)
	require.NoError(t, err)
	hostCatalogId, err := boundary.CreateHostCatalogCli(t, t.Context(), projectId)
	require.NoError(t, err)
	hostSetId, err := boundary.CreateHostSetCli(t, t.Context(), hostCatalogId)
	require.NoError(t, err)
	hostId, err := boundary.CreateHostCli(t, t.Context(), hostCatalogId, c.TargetAddress)
	require.NoError(t, err)
	err = boundary.AddHostToHostSetCli(t, t.Context(), hostSetId, hostId)
	require.NoError(t, err)
	targetId, err := boundary.CreateTargetCli(t, t.Context(), projectId, c.TargetPort, nil)
	require.NoError(t, err)
	err = boundary.AddHostSourceToTargetCli(t, t.Context(), targetId, hostSetId)
	require.NoError(t, err)

	// Configure Vault for LDAP.
	boundaryPolicyName := vault.SetupForBoundaryController(t, "testdata/boundary-controller-policy.hcl")
	t.Cleanup(func() {
		ctx := context.Background()
		output := e2e.RunCommand(ctx, "vault",
			e2e.WithArgs("policy", "delete", boundaryPolicyName),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})

	ldapPolicyName, err := vault.SetupLdapWithOpenLdap(t, c.VaultLdapPath,
		c.LdapAddress, c.LdapAdminDn, c.LdapAdminPassword,
		c.LdapDomainDn, c.LdapUserName, c.LdapGroupName,
	)
	t.Cleanup(func() {
		ctx := context.Background()
		// Destroy LDAP secrets engine and LDAP policy.
		output := e2e.RunCommand(ctx, "vault",
			e2e.WithArgs("secrets", "disable", c.VaultLdapPath),
		)
		require.NoError(t, output.Err, string(output.Stderr))

		output = e2e.RunCommand(ctx, "vault",
			e2e.WithArgs("policy", "delete", ldapPolicyName),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	require.NoError(t, err)

	// Create Vault token for Boundary.
	output := e2e.RunCommand(t.Context(), "vault",
		e2e.WithArgs(
			"token", "create",
			"-no-default-policy=true",
			fmt.Sprintf("-policy=%s", boundaryPolicyName),
			fmt.Sprintf("-policy=%s", ldapPolicyName),
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
	vaultToken := tokenCreateResult.Auth.Client_Token

	// Create two Vault LDAP credential libraries: One with static, one with
	// dynamic creds.
	storeId, err := boundary.CreateCredentialStoreVaultCli(t, t.Context(), projectId, c.VaultAddr, vaultToken)
	require.NoError(t, err)
	staticCredVclId, err := boundary.CreateVaultLdapCredentialLibraryCli(t, t.Context(), storeId, fmt.Sprintf("%s/static-cred/%s", c.VaultLdapPath, c.LdapUserName))
	require.NoError(t, err)
	dynamicCredVclId, err := boundary.CreateVaultLdapCredentialLibraryCli(t, t.Context(), storeId, fmt.Sprintf("%s/creds/%s", c.VaultLdapPath, c.LdapGroupName))
	require.NoError(t, err)
	err = boundary.AddBrokeredCredentialSourceToTargetCli(t, t.Context(), targetId, staticCredVclId)
	require.NoError(t, err)
	err = boundary.AddBrokeredCredentialSourceToTargetCli(t, t.Context(), targetId, dynamicCredVclId)
	require.NoError(t, err)

	// Connect and assert that session credentials exist.
	out := boundary.ConnectCli(t, t.Context(), targetId)
	require.NotEmpty(t, out)

	require.Len(t, out.Credentials, 2) // One for static, one for dynamic role.
	slices.SortFunc(out.Credentials, func(a *targets.SessionCredential, b *targets.SessionCredential) int {
		// Sort by static role credential library first.
		if strings.EqualFold(staticCredVclId, a.CredentialSource.Id) {
			return -1
		}
		return 1
	})

	// Determine the LDAP server's domain using LDAP dn. LdapDomainDn is a
	// string like "dc=subdomain,dc=domain,dc=tld".
	expDomain := strings.ReplaceAll(
		strings.ReplaceAll(c.LdapDomainDn, "dc=", ""), // Transforms into "subdomain,domain,tld".
		",", ".", // Then replace commas with periods to get "subdomain.domain.tld".
	)

	// Static credential.
	require.NotEmpty(t, out.Credentials[0].Credential)
	require.Contains(t, out.Credentials[0].Credential, "username")
	require.Contains(t, out.Credentials[0].Credential, "password")
	require.Contains(t, out.Credentials[0].Credential, "domain")
	require.EqualValues(t, c.LdapUserName, out.Credentials[0].Credential["username"])
	require.NotEmpty(t, out.Credentials[0].Credential["password"])
	require.EqualValues(t, expDomain, out.Credentials[0].Credential["domain"])

	require.NotNil(t, out.Credentials[0].CredentialSource)
	require.EqualValues(t, staticCredVclId, out.Credentials[0].CredentialSource.Id)
	require.Contains(t, out.Credentials[0].CredentialSource.Name, "e2e vault credential library")
	require.EqualValues(t, "vault-ldap", out.Credentials[0].CredentialSource.Type)
	require.EqualValues(t, storeId, out.Credentials[0].CredentialSource.CredentialStoreId)
	require.EqualValues(t, "username_password_domain", out.Credentials[0].CredentialSource.CredentialType)

	require.NotNil(t, out.Credentials[0].Secret)
	require.NotEmpty(t, out.Credentials[0].Secret.Decoded)
	require.Contains(t, out.Credentials[0].Secret.Decoded, "username")
	require.Contains(t, out.Credentials[0].Secret.Decoded, "password")
	require.Contains(t, out.Credentials[0].Secret.Decoded, "dn")
	require.EqualValues(t, c.LdapUserName, out.Credentials[0].Secret.Decoded["username"])
	require.EqualValues(t, out.Credentials[0].Credential["password"], out.Credentials[0].Secret.Decoded["password"])
	require.EqualValues(t, fmt.Sprintf("cn=%s,%s", c.LdapUserName, c.LdapDomainDn), out.Credentials[0].Secret.Decoded["dn"])

	// Dynamic credential.
	require.NotEmpty(t, out.Credentials[1].Credential)
	require.Contains(t, out.Credentials[1].Credential, "username")
	require.Contains(t, out.Credentials[1].Credential, "password")
	require.Contains(t, out.Credentials[1].Credential, "domain")
	require.Contains(t, out.Credentials[1].Credential["username"], fmt.Sprintf("b_token_%s_", c.LdapGroupName))
	require.NotEmpty(t, out.Credentials[1].Credential["password"])
	require.EqualValues(t, expDomain, out.Credentials[1].Credential["domain"])

	require.NotNil(t, out.Credentials[1].CredentialSource)
	require.EqualValues(t, dynamicCredVclId, out.Credentials[1].CredentialSource.Id)
	require.Contains(t, out.Credentials[1].CredentialSource.Name, "e2e vault credential library")
	require.EqualValues(t, "vault-ldap", out.Credentials[1].CredentialSource.Type)
	require.EqualValues(t, storeId, out.Credentials[1].CredentialSource.CredentialStoreId)
	require.EqualValues(t, "username_password_domain", out.Credentials[1].CredentialSource.CredentialType)

	require.NotNil(t, out.Credentials[1].Secret)
	require.NotEmpty(t, out.Credentials[1].Secret.Decoded)
	require.Contains(t, out.Credentials[1].Secret.Decoded, "username")
	require.Contains(t, out.Credentials[1].Secret.Decoded, "password")
	require.Contains(t, out.Credentials[1].Secret.Decoded, "distinguished_names")
	require.EqualValues(t, out.Credentials[1].Credential["username"], out.Credentials[1].Secret.Decoded["username"])
	require.EqualValues(t, out.Credentials[1].Credential["password"], out.Credentials[1].Secret.Decoded["password"])
	distinguishedNames, ok := out.Credentials[1].Secret.Decoded["distinguished_names"].([]any)
	require.True(t, ok)
	require.NotEmpty(t, distinguishedNames)
	require.Contains(t, distinguishedNames, fmt.Sprintf("cn=%s,%s", out.Credentials[1].Secret.Decoded["username"], c.LdapDomainDn))
	require.Contains(t, distinguishedNames, fmt.Sprintf("cn=%s,%s", c.LdapGroupName, c.LdapDomainDn))
}
