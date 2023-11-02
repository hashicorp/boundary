// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package globals

import (
	"strings"

	"github.com/hashicorp/boundary/internal/types/resource"
)

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

	// LdapManagedGroupPrefix defines the prefix for ManagedGroup public ids
	// from the LDAP auth method.
	LdapManagedGroupPrefix = "mgldap"
	// AuthMethodPrefix defines the prefix for AuthMethod public ids.
	LdapAuthMethodPrefix = "amldap"
	// AccountPrefix defines the prefix for Account public ids.
	LdapAccountPrefix = "acctldap"

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
	// DynamicCredentialPrefix is the prefix for Vault dynamic credentials
	VaultDynamicCredentialPrefix = "cdvlt"

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

	// PluginStorageBucketPrefix is the prefix for plugin storage buckets
	PluginStorageBucketPrefix = "sb"

	// SessionRecordingPrefix is the prefix for session recordings
	SessionRecordingPrefix = "sr"
	// ConnectionRecordingPrefix is the prefix for connection recordings
	ConnectionRecordingPrefix = "cr"
	// ChannelRecordingPrefix is the prefix for channel recordings
	ChannelRecordingPrefix = "chr"
)

type ResourceInfo struct {
	Type    resource.Type
	Subtype Subtype
}

var prefixToResourceType = map[string]ResourceInfo{
	AuthTokenPrefix: {
		Type: resource.AuthToken,
	},

	PasswordAuthMethodPrefix: {
		Type:    resource.AuthMethod,
		Subtype: PasswordSubtype,
	},
	PasswordAccountPrefix: {
		Type:    resource.Account,
		Subtype: PasswordSubtype,
	},
	PasswordAccountPreviousPrefix: {
		Type:    resource.Account,
		Subtype: PasswordSubtype,
	},

	OidcAuthMethodPrefix: {
		Type:    resource.AuthMethod,
		Subtype: OidcSubtype,
	},
	OidcAccountPrefix: {
		Type:    resource.Account,
		Subtype: OidcSubtype,
	},
	OidcManagedGroupPrefix: {
		Type:    resource.ManagedGroup,
		Subtype: OidcSubtype,
	},

	LdapManagedGroupPrefix: {
		Type: resource.ManagedGroup,
	},
	LdapAuthMethodPrefix: {
		Type: resource.AuthMethod,
	},
	LdapAccountPrefix: {
		Type: resource.Account,
	},

	ProjectPrefix: {
		Type: resource.Scope,
	},
	OrgPrefix: {
		Type: resource.Scope,
	},
	GlobalPrefix: {
		Type: resource.Scope,
	},

	UserPrefix: {
		Type: resource.User,
	},
	GroupPrefix: {
		Type: resource.Group,
	},
	RolePrefix: {
		Type: resource.Role,
	},

	StaticCredentialStorePrefix: {
		Type:    resource.CredentialStore,
		Subtype: StaticSubtype,
	},
	StaticCredentialStorePreviousPrefix: {
		Type:    resource.CredentialStore,
		Subtype: StaticSubtype,
	},

	VaultCredentialStorePrefix: {
		Type:    resource.CredentialStore,
		Subtype: VaultSubtype,
	},
	VaultCredentialLibraryPrefix: {
		Type:    resource.CredentialLibrary,
		Subtype: VaultGenericLibrarySubtype,
	},
	VaultSshCertificateCredentialLibraryPrefix: {
		Type:    resource.CredentialLibrary,
		Subtype: VaultSshCertificateLibrarySubtype,
	},
	VaultDynamicCredentialPrefix: {
		Type:    resource.Credential,
		Subtype: VaultSubtype,
	},

	UsernamePasswordCredentialPrefix: {
		Type:    resource.Credential,
		Subtype: UsernamePasswordSubtype,
	},
	UsernamePasswordCredentialPreviousPrefix: {
		Type:    resource.Credential,
		Subtype: UsernamePasswordSubtype,
	},
	SshPrivateKeyCredentialPrefix: {
		Type:    resource.Credential,
		Subtype: SshPrivateKeySubtype,
	},
	JsonCredentialPrefix: {
		Type:    resource.Credential,
		Subtype: JsonSubtype,
	},

	StaticHostCatalogPrefix: {
		Type:    resource.HostCatalog,
		Subtype: StaticSubtype,
	},
	StaticHostSetPrefix: {
		Type:    resource.HostSet,
		Subtype: StaticSubtype,
	},
	StaticHostPrefix: {
		Type:    resource.Host,
		Subtype: StaticSubtype,
	},

	PluginHostCatalogPrefix: {
		Type:    resource.HostCatalog,
		Subtype: PluginSubtype,
	},
	PluginHostCatalogPreviousPrefix: {
		Type:    resource.HostCatalog,
		Subtype: PluginSubtype,
	},
	PluginHostSetPrefix: {
		Type:    resource.HostSet,
		Subtype: PluginSubtype,
	},
	PluginHostSetPreviousPrefix: {
		Type:    resource.HostSet,
		Subtype: PluginSubtype,
	},
	PluginHostPrefix: {
		Type:    resource.Host,
		Subtype: PluginSubtype,
	},
	PluginHostPreviousPrefix: {
		Type:    resource.Host,
		Subtype: PluginSubtype,
	},

	SessionPrefix: {
		Type: resource.Session,
	},

	TcpTargetPrefix: {
		Type:    resource.Target,
		Subtype: TcpSubtype,
	},
	SshTargetPrefix: {
		Type:    resource.Target,
		Subtype: SshSubtype,
	},

	WorkerPrefix: {
		Type: resource.Worker,
	},

	PluginStorageBucketPrefix: {
		Type: resource.StorageBucket,
	},

	SessionRecordingPrefix: {
		Type: resource.SessionRecording,
	},
}

var resourceTypeToPrefixes map[resource.Type][]string = func() map[resource.Type][]string {
	ret := make(map[resource.Type][]string)
	for k, v := range prefixToResourceType {
		ret[v.Type] = append(ret[v.Type], k)
	}
	return ret
}()

// ResourceInfoFromPrefix takes in a resource ID (or a prefix) and returns the
// corresponding resource info
func ResourceInfoFromPrefix(in string) ResourceInfo {
	// If full ID, trim to just prefix
	in, _, _ = strings.Cut(in, "_")
	return prefixToResourceType[in]
}

// ResourcePrefixesFromType returns the known prefixes for a given type; if a
// type is not known the return value will be nil
func ResourcePrefixesFromType(in resource.Type) []string {
	return resourceTypeToPrefixes[in]
}
