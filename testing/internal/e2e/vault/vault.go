// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

// Package vault provides methods for commonly used vault actions that are used in end-to-end tests.
package vault

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/stretchr/testify/require"
)

// CreateTokenResponse parses the json response from running `vault token create`
type CreateTokenResponse struct {
	Auth struct {
		Client_Token string
	}
}

// SetupForBoundaryController verifies if appropriate credentials are set and
// adds the boundary controller policy to vault. Returns the policy name.
func SetupForBoundaryController(t testing.TB, boundaryControllerFilePath string) (boundaryPolicyName string) {
	// Set up boundary policy
	boundaryPolicyFilePath, err := filepath.Abs(boundaryControllerFilePath)
	require.NoError(t, err)
	boundaryPolicyName = WritePolicy(t, t.Context(), boundaryPolicyFilePath)

	return boundaryPolicyName
}

// SetupLdapWithAd sets a Vault server up for LDAP against an Active Directory server. It
// enables the LDAP secrets engine, configures it and creates a static user
// according to what is in Active Directory. Note that this function does not put any
// clean-up in place to run after a test is complete. When applicable, callers
// should destroy the Vault LDAP policy this function creates.
func SetupLdapWithAd(t testing.TB, vaultLdapMountPath, ldapAddr, ldapAdmin, ldapAdminPw, ldapUser, ldapDn string) (string, error) {
	// Enable LDAP secrets engine.
	output := e2e.RunCommand(t.Context(), "vault",
		e2e.WithArgs("secrets", "enable", fmt.Sprintf("-path=%s", vaultLdapMountPath), "ldap"),
	)
	if output.Err != nil {
		return "", errors.New(strings.TrimSpace(string(output.Stderr)))
	}

	// Define and write LDAP access policy to Vault.
	vaultLdapPolicyFilePath := path.Join(t.TempDir(), "ldap-policy.hcl")
	f, err := os.Create(vaultLdapPolicyFilePath)
	if err != nil {
		return "", err
	}
	_, err = fmt.Fprintf(f, `
		path "%[1]s/static-cred/%[2]s" {
			capabilities = ["read"]
		}
		path "%[1]s/static-role/%[2]s" {
			capabilities = ["create", "read", "update", "patch", "delete", "list"]
		}
	`, vaultLdapMountPath, ldapUser)
	if err != nil {
		return "", err
	}
	err = f.Sync()
	if err != nil {
		return "", err
	}
	_ = f.Close()

	policyName := WritePolicy(t, t.Context(), vaultLdapPolicyFilePath)

	// Configure LDAP secrets engine to point to AD service.
	output = e2e.RunCommand(t.Context(), "vault",
		e2e.WithArgs(
			"write",
			fmt.Sprintf("%s/config", vaultLdapMountPath),
			fmt.Sprintf("url=%s", ldapAddr),
			fmt.Sprintf("binddn=cn=%s,%s", ldapAdmin, ldapDn),
			fmt.Sprintf("bindpass=%s", ldapAdminPw),
			"schema=ad",
			"insecure_tls=true",
		),
	)
	if output.Err != nil {
		return "", errors.New(strings.TrimSpace(string(output.Stderr)))
	}

	// Create static LDAP user in Vault (already defined in AD server).
	output = e2e.RunCommand(t.Context(), "vault",
		e2e.WithArgs(
			"write",
			fmt.Sprintf("%s/static-role/%s", vaultLdapMountPath, ldapUser),
			fmt.Sprintf("dn=cn=%s,%s", ldapUser, ldapDn),
			fmt.Sprintf("username=%s", ldapUser),
			"rotation_period=24h",
		),
	)
	if output.Err != nil {
		return "", errors.New(strings.TrimSpace(string(output.Stderr)))
	}

	return policyName, nil
}

// SetupLdapWithOpenLdap sets a Vault server up for LDAP against an OpenLDAP server. It
// enables the LDAP secrets engine, configures it and creates a static user
// according to what is in OpenLDAP. Additionally, it sets up Vault's ability to
// manage LDAP users dynamically. Note that this function does not put any
// clean-up in place to run after a test is complete. When applicable, callers
// should destroy the Vault LDAP policy this function creates.
func SetupLdapWithOpenLdap(t testing.TB, vaultLdapMountPath, ldapAddr, ldapAdminDn, ldapAdminPw, ldapDn, ldapUser, ldapGroup string) (string, error) {
	// Enable LDAP secrets engine.
	output := e2e.RunCommand(t.Context(), "vault",
		e2e.WithArgs("secrets", "enable", fmt.Sprintf("-path=%s", vaultLdapMountPath), "ldap"),
	)
	if output.Err != nil {
		return "", errors.New(strings.TrimSpace(string(output.Stderr)))
	}

	// Define and write LDAP access policy to Vault.
	vaultLdapPolicyFilePath := path.Join(t.TempDir(), "ldap-policy.hcl")
	f, err := os.Create(vaultLdapPolicyFilePath)
	if err != nil {
		return "", err
	}

	_, err = fmt.Fprintf(f, `
		path "%[1]s/static-cred/%[2]s" {
			capabilities = ["read"]
		}
		path "%[1]s/static-role/%[2]s" {
			capabilities = ["create", "read", "update", "patch", "delete", "list"]
		}

		path "%[1]s/creds/%[3]s" {
			capabilities = ["read"]
		}
		path "%[1]s/role/%[3]s" {
			capabilities = ["create", "read", "update", "patch", "delete", "list"]
		}
	`, vaultLdapMountPath, ldapUser, ldapGroup)
	if err != nil {
		return "", err
	}
	err = f.Sync()
	if err != nil {
		return "", err
	}
	_ = f.Close()

	policyName := WritePolicy(t, t.Context(), vaultLdapPolicyFilePath)

	// Configure LDAP secrets engine to point to existing OpenLDAP server.
	output = e2e.RunCommand(t.Context(), "vault",
		e2e.WithArgs(
			"write",
			fmt.Sprintf("%s/config", vaultLdapMountPath),
			fmt.Sprintf("url=%s", ldapAddr),
			fmt.Sprintf("binddn=%s", ldapAdminDn),
			fmt.Sprintf("bindpass=%s", ldapAdminPw),
		),
	)
	if output.Err != nil {
		return "", errors.New(strings.TrimSpace(string(output.Stderr)))
	}

	// Create static LDAP user in Vault (already defined in OpenLDAP server).
	output = e2e.RunCommand(t.Context(), "vault",
		e2e.WithArgs(
			"write",
			fmt.Sprintf("%s/static-role/%s", vaultLdapMountPath, ldapUser),
			fmt.Sprintf("dn=cn=%s,%s", ldapUser, ldapDn),
			fmt.Sprintf("username=%s", ldapUser),
			"rotation_period=24h",
		),
	)
	if output.Err != nil {
		return "", errors.New(strings.TrimSpace(string(output.Stderr)))
	}

	// Create Vault dynamic role for LDAP group.
	createLdif := fmt.Sprintf(`
		dn: cn={{.Username}},%[1]s
		changetype: add
		objectClass: inetOrgPerson
		cn: {{.Username}}
		sn: {{.Username}}
		uid: {{.Username}}
		userPassword:{{.Password}}

		dn: cn=%s,%[1]s
		changetype: modify
		add: uniqueMember
		uniqueMember: cn={{.Username}},%[1]s
		-
	`, ldapDn, ldapGroup)
	createLdif = strings.ReplaceAll(createLdif, "\t", "")

	deleteLdif := fmt.Sprintf(`
		dn: cn={{.Username}},%s
		changetype: delete
	`, ldapDn)
	deleteLdif = strings.ReplaceAll(deleteLdif, "\t", "")

	output = e2e.RunCommand(t.Context(), "vault",
		e2e.WithArgs(
			"write",
			fmt.Sprintf("%s/role/%s", vaultLdapMountPath, ldapGroup),
			"username_template=b_{{.DisplayName}}_{{.RoleName}}_{{random 10}}_{{unix_time}}",
			fmt.Sprintf("creation_ldif=%s", createLdif),
			fmt.Sprintf("rollback_ldif=%s", deleteLdif),
			fmt.Sprintf("deletion_ldif=%s", deleteLdif),
			"default_ttl=1h",
			"max_ttxl=24h",
		),
	)
	if output.Err != nil {
		return "", errors.New(strings.TrimSpace(string(output.Stderr)))
	}

	return policyName, nil
}

// CreateKvPrivateKeyCredential creates a private key credential in vault and
// creates a vault policy to be able to read that credential. Returns the secret
// and policy names. Note that this function does not put any clean-up in place
// to run after a test is complete. When applicable, callers should destroy the
// policy and secret this function creates.
func CreateKvPrivateKeyCredential(t testing.TB, secretPath string, user string, keyPath string) (secretName string, policyName string) {
	secretName, err := base62.Random(16)
	require.NoError(t, err)

	policyFilePath := path.Join(t.TempDir(), fmt.Sprintf("kv-pk-%s-policy.hcl", secretName))
	f, err := os.Create(policyFilePath)
	require.NoError(t, err)

	_, err = fmt.Fprintf(f, "path \"%s/data/%s\" { capabilities = [\"read\"] }\n",
		secretPath,
		secretName,
	)
	require.NoError(t, err)

	policyName = WritePolicy(t, t.Context(), policyFilePath)

	// Create secret
	output := e2e.RunCommand(context.Background(), "vault",
		e2e.WithArgs(
			"kv", "put",
			"-mount", secretPath,
			secretName,
			"username="+user,
			"private_key=@"+keyPath,
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	return secretName, policyName
}

// CreateKvPasswordCredential creates a username/password credential in vault
// and creates a vault policy to be able to read that credential. Returns the
// secret and policy names as well as the password for the secret. Note that
// this function does not put any clean-up in place to run after a test is
// complete. When applicable, callers should destroy the policy and secret this
// function creates.
func CreateKvPasswordCredential(t testing.TB, secretPath string, user string, providedPassword ...string) (secretName string, policyName string, password string) {
	secretName, err := base62.Random(16)
	require.NoError(t, err)

	policyFilePath := path.Join(t.TempDir(), fmt.Sprintf("kv-up-%s-policy.hcl", secretName))
	f, err := os.Create(policyFilePath)
	require.NoError(t, err)

	_, err = fmt.Fprintf(f, "path \"%s/data/%s\" { capabilities = [\"read\"] }\n",
		secretPath,
		secretName,
	)
	require.NoError(t, err)

	policyName = WritePolicy(t, t.Context(), policyFilePath)

	// Use provided password or generate random one
	if len(providedPassword) > 0 && providedPassword[0] != "" {
		password = providedPassword[0]
	} else {
		password, err = base62.Random(16)
		require.NoError(t, err)
	}

	// Escape '@' in the password. Vault CLI interprets '@' as a file
	escapedPassword := strings.ReplaceAll(password, "@", "\\@")

	// Create secret
	output := e2e.RunCommand(context.Background(), "vault",
		e2e.WithArgs(
			"kv", "put",
			"-mount", secretPath,
			secretName,
			fmt.Sprintf("username=%s", user),
			fmt.Sprintf("password=%s", escapedPassword),
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	return secretName, policyName, password
}

// CreateKvPasswordDomainCredential creates a username/password/domain
// credential in vault and creates a vault policy to be able to read that
// credential. Returns the name of the policy. Note that this function does not
// put any clean-up in place to run after a test is complete. When applicable,
// callers should destroy the policy and secret this function creates.
func CreateKvPasswordDomainCredential(t testing.TB, secretPath string, user string, domain string, providedPassword ...string) (secretName string, policyName string, password string) {
	secretName, err := base62.Random(16)
	require.NoError(t, err)

	policyFilePath := path.Join(t.TempDir(), fmt.Sprintf("kv-upd-%s-policy.hcl", secretName))
	f, err := os.Create(policyFilePath)
	require.NoError(t, err)

	_, err = fmt.Fprintf(f, "path \"%s/data/%s\" { capabilities = [\"read\"] }\n",
		secretPath,
		secretName,
	)
	require.NoError(t, err)

	policyName = WritePolicy(t, t.Context(), policyFilePath)

	// Use provided password or generate random one
	if len(providedPassword) > 0 && providedPassword[0] != "" {
		password = providedPassword[0]
	} else {
		password, err = base62.Random(16)
		require.NoError(t, err)
	}

	// Escape '@' in the password. Vault CLI interprets '@' as a file
	escapedPassword := strings.ReplaceAll(password, "@", "\\@")

	// Create secret
	output := e2e.RunCommand(context.Background(), "vault",
		e2e.WithArgs(
			"kv", "put",
			"-mount", secretPath,
			secretName,
			fmt.Sprintf("username=%s", user),
			fmt.Sprintf("password=%s", escapedPassword),
			fmt.Sprintf("domain=%s", domain),
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	return secretName, policyName, password
}

// WritePolicy adds a policy to vault. Provide a name for the policy that you want to create as well
// as the path to the file that contains the policy definition. Returns a policy name
func WritePolicy(t testing.TB, ctx context.Context, policyFilePath string) string {
	policyName, err := base62.Random(16)
	require.NoError(t, err)

	output := e2e.RunCommand(ctx, "vault",
		e2e.WithArgs("policy", "write", policyName, policyFilePath),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	return policyName
}
