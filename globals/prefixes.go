// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package globals

// This set of consts is intended to be a place to collect commonly-used
// prefixes. This can avoid some cross-package dependency issues. Unlike the
// top-level globals package, these are not currently meant to be available to
// clients or test writers.

const (
	// AuthTokenPrefix is the prefix for auth tokens
	AuthTokenPrefix = "at"

	// PasswordAuthMethodPrefix is the prefix for the password auth method
	PasswordAuthMethodPrefix = "ampw"
	// PasswordAccountPreviousPrefix is the previously-used account prefix
	PasswordAccountPreviousPrefix = "apw"
	// PasswordAccountPrefix is the new account prefix
	PasswordAccountPrefix = "acctpw"

	// OidcAuthMethodPrefix defines the prefix for OIDC AuthMethod public ids
	OidcAuthMethodPrefix = "amoidc"
	// OidcAccountPrefix defines the prefix for OIDC Account public ids
	OidcAccountPrefix = "acctoidc"
	// OidcManagedGroupPrefix defines the prefix for OIDC ManagedGroup public
	// ids
	OidcManagedGroupPrefix = "mgoidc"

	// ProjectPrefix is the prefix for project scopes
	ProjectPrefix = "p"
	// OrgPrefix is the prefix for org scopes
	OrgPrefix = "o"
	// GlobalPrefix is the prefix for the global scope
	GlobalPrefix = "global"

	// UserPrefix is the prefix for users
	UserPrefix = "u"
	// GroupPrefix is the prefix for non-managed groups
	GroupPrefix = "g"
	// RolePrefix is the prefix for roles
	RolePrefix = "r"

	// StaticCredentialStorePrefix is the prefix for static credential stores
	StaticCredentialStorePrefix = "csst"
	// StaticPreviousCredentialStorePrefix is the previous prefix for static
	// credential stores
	StaticCredentialStorePreviousPrefix = "cs"

	// VaultCredentialStorePrefix is the prefix for Vault credential stores
	VaultCredentialStorePrefix = "csvlt"
	// VaultCredentialLibraryPrefix is the prefix for Vault credential libraries
	VaultCredentialLibraryPrefix = "clvlt"
	// VaultSshCertificateCredentialLibraryPrefix is the prefix for Vault SSH
	// certificate credential libraries
	VaultSshCertificateCredentialLibraryPrefix = "clvsclt"
)
