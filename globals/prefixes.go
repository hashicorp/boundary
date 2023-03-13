// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package globals

import "strings"

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

	// UsernamePasswordCredentialPrefix is the prefix for username/password
	// creds
	UsernamePasswordCredentialPrefix = "credup"
	// UsernamePasswordCredentialPreviousPrefix is the previous prefix for
	// username/password creds
	UsernamePasswordCredentialPreviousPrefix = "cred"
	// SshPrivateKeyCredentialPrefix is the prefix for SSH private key creds
	SshPrivateKeyCredentialPrefix = "credspk"
	// JsonCredentialPrefix is the prefix for generic JSON creds
	JsonCredentialPrefix = "credjson"

	// StaticHostCatalogPrefix is the prefix for static host catalogs
	StaticHostCatalogPrefix = "hcst"
	// StaticHostSetPrefix is the prefix for static host sets
	StaticHostSetPrefix = "hsst"
	// StaticHostPrefix is the prefix for static hosts
	StaticHostPrefix = "hst"

	// PluginHostCatalogPrefix is the prefix for plugin host catalogs
	PluginHostCatalogPrefix = "hcplg"
	// PluginHostCatalogPreviousPrefix is the previous prefix for plugin host
	// catalogs
	PluginHostCatalogPreviousPrefix = "hc"
	// PluginHostSetPrefix is the prefix for plugin host sets
	PluginHostSetPrefix = "hsplg"
	// PluginHostSetPreviousPrefix is the previous prefix for plugin host sets
	PluginHostSetPreviousPrefix = "hs"
	// PluginHostPrefix is the prefix for plugin hosts
	PluginHostPrefix = "hplg"
	// PluginHostPreviousPrefix is the previous prefix for plugin hosts
	PluginHostPreviousPrefix = "h"

	// SessionPrefix is the prefix for sessions
	SessionPrefix = "s"

	// TcpTargetPrefix is the prefix for TCP targets
	TcpTargetPrefix = "ttcp"
	// SshTargetPrefix is the prefix for TCP targets
	SshTargetPrefix = "tssh"

	// WorkerPrefix is the prefix for workers
	WorkerPrefix = "w"
)

var topLevelPrefixes = map[string]bool{
	AuthTokenPrefix:                     true,
	PasswordAuthMethodPrefix:            true,
	OidcAuthMethodPrefix:                true,
	ProjectPrefix:                       true,
	OrgPrefix:                           true,
	UserPrefix:                          true,
	GroupPrefix:                         true,
	RolePrefix:                          true,
	StaticCredentialStorePrefix:         true,
	StaticCredentialStorePreviousPrefix: true,
	VaultCredentialStorePrefix:          true,
	StaticHostCatalogPrefix:             true,
	PluginHostCatalogPrefix:             true,
	PluginHostCatalogPreviousPrefix:     true,
	SessionPrefix:                       true,
	TcpTargetPrefix:                     true,
	SshTargetPrefix:                     true,
	WorkerPrefix:                        true,
}

// IsTopLevelResourcePrefix takes in a resource ID (or a prefix) and indicates
// via the result whether the ID/prefix corresponds to a top-level resource;
// that is, one (like auth method) that does not have a parent (like account or
// managed group)
func IsTopLevelResourcePrefix(in string) bool {
	// If full ID, trim to just prefix
	in, _, _ = strings.Cut(in, "_")
	return topLevelPrefixes[in]
}
