// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package globals

import (
	"fmt"
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
	// VaultLdapCredentialLibraryPrefix is the prefix for Vault Ldap credential libraries
	VaultLdapCredentialLibraryPrefix = "clvllt"

	// UsernamePasswordCredentialPrefix is the prefix for username/password
	// creds
	UsernamePasswordCredentialPrefix = "credup"
	// UsernamePasswordDomainCredentialPrefix is the prefix for username/password/domain
	// creds
	UsernamePasswordDomainCredentialPrefix = "credupd"
	// UsernamePasswordCredentialPreviousPrefix is the previous prefix for
	// username/password creds
	UsernamePasswordCredentialPreviousPrefix = "cred"
	// PasswordCredentialPrefix is the prefix for password creds
	PasswordCredentialPrefix = "credp"
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
	// RdpTargetPrefix is the prefix for RDP targets
	RdpTargetPrefix = "trdp"

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

	// StoragePolicyPrefix for storage policies.
	StoragePolicyPrefix = "pst"

	// TargetAliasPrefix is the prefix for target aliases
	TargetAliasPrefix = "alt"

	// ProxyServerCertificatePrefix is the prefix for proxy server certificates
	ProxyServerCertificatePrefix = "psc"
)

type ResourceInfo struct {
	Type    resource.Type
	Domain  string
	Subtype Subtype
}

var prefixToResourceType = map[string]ResourceInfo{
	AuthTokenPrefix: {
		Type:    resource.AuthToken,
		Subtype: UnknownSubtype,
	},

	PasswordAuthMethodPrefix: {
		Type:    resource.AuthMethod,
		Subtype: UnknownSubtype,
	},
	PasswordAccountPrefix: {
		Type:    resource.Account,
		Subtype: UnknownSubtype,
	},
	PasswordAccountPreviousPrefix: {
		Type:    resource.Account,
		Subtype: UnknownSubtype,
	},

	OidcAuthMethodPrefix: {
		Type:    resource.AuthMethod,
		Subtype: UnknownSubtype,
	},
	OidcAccountPrefix: {
		Type:    resource.Account,
		Subtype: UnknownSubtype,
	},
	OidcManagedGroupPrefix: {
		Type:    resource.ManagedGroup,
		Subtype: UnknownSubtype,
	},

	LdapManagedGroupPrefix: {
		Type:    resource.ManagedGroup,
		Subtype: UnknownSubtype,
	},
	LdapAuthMethodPrefix: {
		Type:    resource.AuthMethod,
		Subtype: UnknownSubtype,
	},
	LdapAccountPrefix: {
		Type:    resource.Account,
		Subtype: UnknownSubtype,
	},

	ProjectPrefix: {
		Type:    resource.Scope,
		Subtype: UnknownSubtype,
	},
	OrgPrefix: {
		Type:    resource.Scope,
		Subtype: UnknownSubtype,
	},
	GlobalPrefix: {
		Type:    resource.Scope,
		Subtype: UnknownSubtype,
	},

	UserPrefix: {
		Type:    resource.User,
		Subtype: UnknownSubtype,
	},
	GroupPrefix: {
		Type:    resource.Group,
		Subtype: UnknownSubtype,
	},
	RolePrefix: {
		Type:    resource.Role,
		Subtype: UnknownSubtype,
	},

	StaticCredentialStorePrefix: {
		Type:    resource.CredentialStore,
		Subtype: UnknownSubtype,
	},
	StaticCredentialStorePreviousPrefix: {
		Type:    resource.CredentialStore,
		Subtype: UnknownSubtype,
	},

	TargetAliasPrefix: {
		Type:    resource.Alias,
		Subtype: UnknownSubtype,
	},

	VaultCredentialStorePrefix: {
		Type:    resource.CredentialStore,
		Subtype: UnknownSubtype,
	},
	VaultCredentialLibraryPrefix: {
		Type:    resource.CredentialLibrary,
		Subtype: UnknownSubtype,
	},
	VaultSshCertificateCredentialLibraryPrefix: {
		Type:    resource.CredentialLibrary,
		Subtype: UnknownSubtype,
	},
	VaultLdapCredentialLibraryPrefix: {
		Type:    resource.CredentialLibrary,
		Subtype: UnknownSubtype,
	},
	VaultDynamicCredentialPrefix: {
		Type:    resource.Credential,
		Subtype: UnknownSubtype,
	},

	UsernamePasswordCredentialPrefix: {
		Type:    resource.Credential,
		Subtype: UnknownSubtype,
	},
	UsernamePasswordDomainCredentialPrefix: {
		Type:    resource.Credential,
		Subtype: UnknownSubtype,
	},
	UsernamePasswordCredentialPreviousPrefix: {
		Type:    resource.Credential,
		Subtype: UnknownSubtype,
	},
	PasswordCredentialPrefix: {
		Type:    resource.Credential,
		Subtype: UnknownSubtype,
	},
	SshPrivateKeyCredentialPrefix: {
		Type:    resource.Credential,
		Subtype: UnknownSubtype,
	},
	JsonCredentialPrefix: {
		Type:    resource.Credential,
		Subtype: UnknownSubtype,
	},

	StaticHostCatalogPrefix: {
		Type:    resource.HostCatalog,
		Subtype: UnknownSubtype,
	},
	StaticHostSetPrefix: {
		Type:    resource.HostSet,
		Subtype: UnknownSubtype,
	},
	StaticHostPrefix: {
		Type:    resource.Host,
		Subtype: UnknownSubtype,
	},

	PluginHostCatalogPrefix: {
		Type:    resource.HostCatalog,
		Subtype: UnknownSubtype,
	},
	PluginHostCatalogPreviousPrefix: {
		Type:    resource.HostCatalog,
		Subtype: UnknownSubtype,
	},
	PluginHostSetPrefix: {
		Type:    resource.HostSet,
		Subtype: UnknownSubtype,
	},
	PluginHostSetPreviousPrefix: {
		Type:    resource.HostSet,
		Subtype: UnknownSubtype,
	},
	PluginHostPrefix: {
		Type:    resource.Host,
		Subtype: UnknownSubtype,
	},
	PluginHostPreviousPrefix: {
		Type:    resource.Host,
		Subtype: UnknownSubtype,
	},

	SessionPrefix: {
		Type:    resource.Session,
		Subtype: UnknownSubtype,
	},

	TcpTargetPrefix: {
		Type:    resource.Target,
		Subtype: UnknownSubtype,
	},
	SshTargetPrefix: {
		Type:    resource.Target,
		Subtype: UnknownSubtype,
	},
	RdpTargetPrefix: {
		Type:    resource.Target,
		Subtype: UnknownSubtype,
	},

	WorkerPrefix: {
		Type:    resource.Worker,
		Subtype: UnknownSubtype,
	},

	PluginStorageBucketPrefix: {
		Type:    resource.StorageBucket,
		Subtype: UnknownSubtype,
	},

	SessionRecordingPrefix: {
		Type:    resource.SessionRecording,
		Subtype: UnknownSubtype,
	},

	StoragePolicyPrefix: {
		Type:    resource.Policy,
		Subtype: UnknownSubtype,
	},
}

var resourceTypeToPrefixes map[resource.Type][]string = func() map[resource.Type][]string {
	ret := make(map[resource.Type][]string)
	for k, v := range prefixToResourceType {
		ret[v.Type] = append(ret[v.Type], k)
	}
	return ret
}()

// RegisterPrefixToResourceInfo is called from various packages to register
// which prefixes belong to them, what types those represent, and any
// domain and subtype information. This lets the subtypes stay in different
// packages (important for the reflection introspection we do) while not
// creating import loops.
//
// If called more than once for the same prefix, this function will panic.
func RegisterPrefixToResourceInfo(prefix string, res resource.Type, domain string, subtype Subtype) {
	if subtype == UnknownSubtype {
		panic("cannot be called with a subtype of Unknown")
	}
	resInfo, ok := prefixToResourceType[prefix]
	if !ok && domain != "test" {
		panic(fmt.Sprintf("prefix %q being registered to domain %q type %q subtype %q but did not already exist in map", prefix, domain, res.String(), subtype.String()))
	}
	if domain != "test" &&
		(resInfo.Domain != "" ||
			resInfo.Subtype != UnknownSubtype) {
		panic(fmt.Sprintf("prefix %q being registered to domain %q type %q subtype %q but was already registered to domain %q type %q subtype %q", prefix, domain, res.String(), subtype.String(), resInfo.Domain, resInfo.Type.String(), resInfo.Subtype.String()))
	}
	resInfo.Type = res
	resInfo.Subtype = subtype
	resInfo.Domain = domain
	prefixToResourceType[prefix] = resInfo
}

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

func PrefixesFromDomain(domain string) []string {
	res := make([]string, 0, 8)
	for k, v := range prefixToResourceType {
		if v.Domain == domain {
			res = append(res, k)
		}
	}
	return res
}
