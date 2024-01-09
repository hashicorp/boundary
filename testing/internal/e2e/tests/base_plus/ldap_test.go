// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_plus_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/hashicorp/boundary/api/accounts"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/api/managedgroups"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/require"
)

// TestCliLdap uses the boundary cli to set up an LDAP auth method and confirm
// that an LDAP user can authenticate to boundary. It also confirms that an LDAP
// managed group can be added as a principal to a role.
func TestCliLdap(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
	require.NoError(t, err)

	ctx := context.Background()
	boundary.AuthenticateAdminCli(t, ctx)
	newOrgId := boundary.CreateNewOrgCli(t, ctx)
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("scopes", "delete", "-id", newOrgId))
		require.NoError(t, output.Err, string(output.Stderr))
	})

	// Create an LDAP auth method
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"auth-methods", "create", "ldap",
			"-scope-id", newOrgId,
			"-name", "e2e LDAP",
			"-urls", c.LdapAddress,
			"-user-dn", c.LdapDomainDn,
			"-user-attr", "uid",
			"-group-dn", c.LdapDomainDn,
			"-bind-dn", c.LdapAdminDn,
			"-bind-password", "env://LDAP_PW",
			"-state", "active-public",
			"-enable-groups=true",
			"-discover-dn=true",
			"-format", "json",
		),
		e2e.WithEnv("LDAP_PW", c.LdapAdminPassword),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newAuthMethodResult authmethods.AuthMethodCreateResult
	err = json.Unmarshal(output.Stdout, &newAuthMethodResult)
	require.NoError(t, err)
	ldapAuthMethodId := newAuthMethodResult.Item.Id
	t.Logf("Create Auth Method: %s", ldapAuthMethodId)

	// Create an LDAP account
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"accounts", "create", "ldap",
			"-auth-method-id", ldapAuthMethodId,
			"-name", "einstein",
			"-login-name", c.LdapUserName,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newAccountResult accounts.AccountCreateResult
	err = json.Unmarshal(output.Stdout, &newAccountResult)
	require.NoError(t, err)
	newAccountId := newAccountResult.Item.Id
	t.Logf("Created Account: %s", newAccountId)

	// Create a user and attach the LDAP account
	newUserId := boundary.CreateNewUserCli(t, ctx, newOrgId)
	boundary.SetAccountToUserCli(t, ctx, newUserId, newAccountId)

	// Try to log in with the wrong password
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"authenticate", "ldap",
			"-auth-method-id", ldapAuthMethodId,
			"-login-name", c.LdapUserName,
			"-password", "env://LDAP_PW",
		),
		e2e.WithEnv("LDAP_PW", c.LdapAdminPassword),
	)
	require.Error(t, output.Err, string(output.Stderr))

	// Log in as the LDAP user
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"authenticate", "ldap",
			"-auth-method-id", ldapAuthMethodId,
			"-login-name", c.LdapUserName,
			"-password", "env://LDAP_PW",
		),
		e2e.WithEnv("LDAP_PW", c.LdapUserPassword),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Confirm there is a permissions error when trying to read an auth method
	// as an LDAP user
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"auth-methods", "read",
			"-id", ldapAuthMethodId,
			"-format", "json",
		),
	)
	require.Error(t, output.Err, string(output.Stderr))
	var response boundary.CliError
	err = json.Unmarshal(output.Stderr, &response)
	require.NoError(t, err)
	require.Equal(t, http.StatusForbidden, response.Status)

	// Create an LDAP managed group
	boundary.AuthenticateAdminCli(t, ctx)
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"managed-groups", "create", "ldap",
			"-auth-method-id", ldapAuthMethodId,
			"-name", c.LdapGroupName,
			"-group-names", c.LdapGroupName,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	var newManagedGroupResult managedgroups.ManagedGroupCreateResult
	err = json.Unmarshal(output.Stdout, &newManagedGroupResult)
	require.NoError(t, err)
	managedGroupId := newManagedGroupResult.Item.Id
	t.Logf("Created Managed Group: %s", managedGroupId)

	// Confirm that LDAP user is in the managed group
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
	require.Contains(t, managedGroupReadResult.Item.MemberIds, newAccountId)

	// Add managed group as a principal to a role with permissions to read auth methods
	newRoleId := boundary.CreateNewRoleCli(t, ctx, newOrgId)
	boundary.AddPrincipalToRoleCli(t, ctx, newRoleId, managedGroupId)
	boundary.AddGrantToRoleCli(t, ctx, newRoleId, "ids=*;type=auth-method;actions=read")

	// Log in as the LDAP user again
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"authenticate", "ldap",
			"-auth-method-id", ldapAuthMethodId,
			"-login-name", c.LdapUserName,
			"-password", "env://LDAP_PW",
		),
		e2e.WithEnv("LDAP_PW", c.LdapUserPassword),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Read the auth method. Expect no error
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"auth-methods", "read",
			"-id", ldapAuthMethodId,
			"-format", "json",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
}
