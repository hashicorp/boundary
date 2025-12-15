// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"github.com/hashicorp/boundary/internal/types/resource"
)

type cmdInfo struct {
	// The type of the resource, e.g. "target"
	ResourceType string

	// The API package under the api path
	Pkg string

	// Standard actions (with standard parameters) used by this resource
	StdActions []string

	// HasCustomList indicates if there is a custom list action
	HasCustomList bool

	// HasExtraCommandVars controls whether to generate an embedded struct with
	// extra command variables
	HasExtraCommandVars bool

	// SkipNormalHelp indicates skipping the normal help case for when it needs
	// to be only custom (mainly for subactions)
	SkipNormalHelp bool

	// HasExtraHelpFunc controls whether to include a default statement chaining
	// to an extra help function
	HasExtraHelpFunc bool

	// HasExampleCliOutput controls whether to generate code to look for a CLI
	// output env var and print
	HasExampleCliOutput bool

	// HasId controls whether to add ID emptiness checking. Note that some
	// commands that allow name/scope id or name/scope name handling may skip
	// this in favor of custom logic.
	HasId bool

	// Container controls what to generate for a required container (scope ID,
	// auth method ID, etc.)
	Container string

	// HasName controls whether to add name options
	HasName bool

	// HasDescription controls whether to add description options
	HasDescription bool

	// HasScopeName controls whether to add scope name options
	HasScopeName bool

	// VersionedActions controls which actions to add a case for version checking
	VersionedActions []string

	// SubActionPrefix specifies the prefix to use when generating sub-action
	// commands (e.g. "targets update tcp")
	SubActionPrefix string

	// NeedsSubtypeInCreate controls whether the sub-type must be passed in as
	// an argument to a create call. Targets need this, accounts do not, etc.
	NeedsSubtypeInCreate bool

	// PrefixAttributeFieldErrorsWithSubactionPrefix will prepend the value in
	// SubActionPrefix when reporting errors which are reported in flag format.
	// This allows the flags to be defined differently from the the attribute
	// names in the API.
	PrefixAttributeFieldErrorsWithSubactionPrefix bool

	// HasGenericAttributes controls whether to generate flags for -attributes,
	// -attr, -string-attr, etc.
	HasGenericAttributes bool

	// HasGenericSecrets controls whether to generate flags for -secrets,
	// -secret, -string-secret, etc.
	HasGenericSecrets bool

	// HasJsonObject controls whether to generate flags for -object,
	// -kv, -string-kv, -bool-kv, -num-kv.
	HasJsonObject bool

	// IsPluginType controls whether standard plugin flags are generated
	IsPluginType bool

	// SkipClientCallActions allows skipping creation of an actual client
	// call for an action in favor of custom logic in extra actions
	SkipClientCallActions []string

	SkipFiltering bool

	// UsesAlias controls whether to attempt to extract aliases from the CLI args
	UsesAlias bool

	// AliasFieldFlag controls which command flag to substitute a found alias for
	AliasFieldFlag string

	// FlagNameOverwrittenByAlias is used in the CLI template to populate an error message.
	// It controls what to print as the field replaced by an alias
	// if both an alias and the FlagNameOverwrittenByAlias are provided.
	FlagNameOverwrittenByAlias string
}

var inputStructs = map[string][]*cmdInfo{
	"accounts": {
		{
			ResourceType:        resource.Account.String(),
			Pkg:                 "accounts",
			StdActions:          []string{"read", "delete", "list"},
			HasExtraCommandVars: true,
			HasExtraHelpFunc:    true,
			Container:           "AuthMethod",
			HasId:               true,
			HasName:             true,
			HasDescription:      true,
			VersionedActions:    []string{"change-password", "set-password"},
		},
		{
			ResourceType:        resource.Account.String(),
			Pkg:                 "accounts",
			StdActions:          []string{"create", "update"},
			SubActionPrefix:     "password",
			HasExtraCommandVars: true,
			SkipNormalHelp:      true,
			HasExtraHelpFunc:    true,
			HasId:               true,
			HasName:             true,
			Container:           "AuthMethod",
			HasDescription:      true,
			VersionedActions:    []string{"update"},
		},
		{
			ResourceType:        resource.Account.String(),
			Pkg:                 "accounts",
			StdActions:          []string{"create", "update"},
			SubActionPrefix:     "oidc",
			HasExtraCommandVars: true,
			SkipNormalHelp:      true,
			HasExtraHelpFunc:    true,
			HasId:               true,
			HasName:             true,
			Container:           "AuthMethod",
			HasDescription:      true,
			VersionedActions:    []string{"update"},
		},
		{
			ResourceType:        resource.Account.String(),
			Pkg:                 "accounts",
			StdActions:          []string{"create", "update"},
			SubActionPrefix:     "ldap",
			HasExtraCommandVars: true,
			SkipNormalHelp:      true,
			HasExtraHelpFunc:    true,
			HasId:               true,
			HasName:             true,
			Container:           "AuthMethod",
			HasDescription:      true,
			VersionedActions:    []string{"update"},
		},
	},
	"aliases": {
		{
			ResourceType:     resource.Alias.String(),
			Pkg:              "aliases",
			StdActions:       []string{"read", "delete", "list"},
			HasExtraHelpFunc: true,
			Container:        "Scope",
			HasId:            true,
		},
		{
			ResourceType:         resource.Alias.String(),
			Pkg:                  "aliases",
			StdActions:           []string{"create", "update"},
			SubActionPrefix:      "target",
			HasExtraCommandVars:  true,
			SkipNormalHelp:       true,
			HasExtraHelpFunc:     true,
			HasId:                true,
			HasName:              true,
			HasDescription:       true,
			Container:            "Scope",
			VersionedActions:     []string{"update"},
			NeedsSubtypeInCreate: true,
		},
	},
	"authmethods": {
		{
			ResourceType:     resource.AuthMethod.String(),
			Pkg:              "authmethods",
			StdActions:       []string{"read", "delete", "list"},
			HasExtraHelpFunc: true,
			Container:        "Scope",
			HasId:            true,
		},
		{
			ResourceType:         resource.AuthMethod.String(),
			Pkg:                  "authmethods",
			StdActions:           []string{"create", "update"},
			SubActionPrefix:      "password",
			HasExtraCommandVars:  true,
			SkipNormalHelp:       true,
			HasExtraHelpFunc:     true,
			HasId:                true,
			HasName:              true,
			HasDescription:       true,
			Container:            "Scope",
			VersionedActions:     []string{"update"},
			NeedsSubtypeInCreate: true,
		},
		{
			ResourceType:         resource.AuthMethod.String(),
			Pkg:                  "authmethods",
			StdActions:           []string{"create", "update"},
			SubActionPrefix:      "oidc",
			HasExtraCommandVars:  true,
			SkipNormalHelp:       true,
			HasExtraHelpFunc:     true,
			HasId:                true,
			HasName:              true,
			HasDescription:       true,
			Container:            "Scope",
			VersionedActions:     []string{"update", "change-state"},
			NeedsSubtypeInCreate: true,
		},
		{
			ResourceType:         resource.AuthMethod.String(),
			Pkg:                  "authmethods",
			StdActions:           []string{"create", "update"},
			SubActionPrefix:      "ldap",
			HasExtraCommandVars:  true,
			SkipNormalHelp:       true,
			HasExtraHelpFunc:     true,
			HasId:                true,
			HasName:              true,
			HasDescription:       true,
			Container:            "Scope",
			VersionedActions:     []string{"update"},
			NeedsSubtypeInCreate: true,
		},
	},
	"authtokens": {
		{
			ResourceType:     resource.AuthToken.String(),
			Pkg:              "authtokens",
			StdActions:       []string{"read", "delete", "list"},
			HasExtraHelpFunc: true,
			Container:        "Scope",
		},
	},
	"billing": {
		{
			ResourceType:        resource.Billing.String(),
			Pkg:                 "billing",
			HasCustomList:       true,
			HasExtraCommandVars: true,
			HasExtraHelpFunc:    true,
		},
	},
	"credentialstores": {
		{
			ResourceType:     resource.CredentialStore.String(),
			Pkg:              "credentialstores",
			StdActions:       []string{"read", "delete", "list"},
			HasExtraHelpFunc: true,
			Container:        "Scope",
			HasId:            true,
		},
		{
			ResourceType:         resource.CredentialStore.String(),
			Pkg:                  "credentialstores",
			StdActions:           []string{"create", "update"},
			SubActionPrefix:      "vault",
			HasExtraCommandVars:  true,
			SkipNormalHelp:       true,
			HasExtraHelpFunc:     true,
			HasId:                true,
			HasName:              true,
			HasDescription:       true,
			Container:            "Scope",
			VersionedActions:     []string{"update"},
			NeedsSubtypeInCreate: true,
			PrefixAttributeFieldErrorsWithSubactionPrefix: true,
		},
		{
			ResourceType:         resource.CredentialStore.String(),
			Pkg:                  "credentialstores",
			StdActions:           []string{"create", "update"},
			SubActionPrefix:      "static",
			SkipNormalHelp:       true,
			HasExtraHelpFunc:     true,
			HasId:                true,
			HasName:              true,
			HasDescription:       true,
			Container:            "Scope",
			VersionedActions:     []string{"update"},
			NeedsSubtypeInCreate: true,
			PrefixAttributeFieldErrorsWithSubactionPrefix: true,
		},
	},
	"credentiallibraries": {
		{
			ResourceType:     resource.CredentialLibrary.String(),
			Pkg:              "credentiallibraries",
			StdActions:       []string{"read", "delete", "list"},
			HasExtraHelpFunc: true,
			Container:        "CredentialStore",
			HasId:            true,
		},
		{
			ResourceType:         resource.CredentialLibrary.String(),
			Pkg:                  "credentiallibraries",
			StdActions:           []string{"create", "update"},
			SubActionPrefix:      "vault",
			HasExtraCommandVars:  true,
			SkipNormalHelp:       true,
			HasExtraHelpFunc:     true,
			HasId:                true,
			HasName:              true,
			HasDescription:       true,
			NeedsSubtypeInCreate: true,
			Container:            "CredentialStore",
			VersionedActions:     []string{"update"},
			PrefixAttributeFieldErrorsWithSubactionPrefix: true,
		},
		{
			ResourceType:         resource.CredentialLibrary.String(),
			Pkg:                  "credentiallibraries",
			StdActions:           []string{"create", "update"},
			SubActionPrefix:      "vault-generic",
			HasExtraCommandVars:  true,
			SkipNormalHelp:       true,
			HasExtraHelpFunc:     true,
			HasId:                true,
			HasName:              true,
			HasDescription:       true,
			NeedsSubtypeInCreate: true,
			Container:            "CredentialStore",
			VersionedActions:     []string{"update"},
			PrefixAttributeFieldErrorsWithSubactionPrefix: true,
		},
		{
			ResourceType:         resource.CredentialLibrary.String(),
			Pkg:                  "credentiallibraries",
			StdActions:           []string{"create", "update"},
			SubActionPrefix:      "vault-ssh-certificate",
			HasExtraCommandVars:  true,
			SkipNormalHelp:       true,
			HasExtraHelpFunc:     true,
			HasId:                true,
			HasName:              true,
			HasDescription:       true,
			NeedsSubtypeInCreate: true,
			Container:            "CredentialStore",
			VersionedActions:     []string{"update"},
			PrefixAttributeFieldErrorsWithSubactionPrefix: true,
		},
		{
			ResourceType:         resource.CredentialLibrary.String(),
			Pkg:                  "credentiallibraries",
			StdActions:           []string{"create", "update"},
			SubActionPrefix:      "vault-ldap",
			HasExtraCommandVars:  true,
			SkipNormalHelp:       true,
			HasExtraHelpFunc:     true,
			HasId:                true,
			HasName:              true,
			HasDescription:       true,
			NeedsSubtypeInCreate: true,
			Container:            "CredentialStore",
			VersionedActions:     []string{"update"},
			PrefixAttributeFieldErrorsWithSubactionPrefix: true,
		},
	},
	"credentials": {
		{
			ResourceType:     resource.Credential.String(),
			Pkg:              "credentials",
			StdActions:       []string{"read", "delete", "list"},
			HasExtraHelpFunc: true,
			Container:        "CredentialStore",
			HasId:            true,
		},
		{
			ResourceType:         resource.Credential.String(),
			Pkg:                  "credentials",
			StdActions:           []string{"create", "update"},
			SubActionPrefix:      "password",
			HasExtraCommandVars:  true,
			SkipNormalHelp:       true,
			HasExtraHelpFunc:     true,
			HasId:                true,
			HasName:              true,
			HasDescription:       true,
			Container:            "CredentialStore",
			VersionedActions:     []string{"update"},
			NeedsSubtypeInCreate: true,
			PrefixAttributeFieldErrorsWithSubactionPrefix: true,
		},
		{
			ResourceType:         resource.Credential.String(),
			Pkg:                  "credentials",
			StdActions:           []string{"create", "update"},
			SubActionPrefix:      "username_password",
			HasExtraCommandVars:  true,
			SkipNormalHelp:       true,
			HasExtraHelpFunc:     true,
			HasId:                true,
			HasName:              true,
			HasDescription:       true,
			Container:            "CredentialStore",
			VersionedActions:     []string{"update"},
			NeedsSubtypeInCreate: true,
			PrefixAttributeFieldErrorsWithSubactionPrefix: true,
		},
		{
			ResourceType:         resource.Credential.String(),
			Pkg:                  "credentials",
			StdActions:           []string{"create", "update"},
			SubActionPrefix:      "username_password_domain",
			HasExtraCommandVars:  true,
			SkipNormalHelp:       true,
			HasExtraHelpFunc:     true,
			HasId:                true,
			HasName:              true,
			HasDescription:       true,
			Container:            "CredentialStore",
			VersionedActions:     []string{"update"},
			NeedsSubtypeInCreate: true,
			PrefixAttributeFieldErrorsWithSubactionPrefix: true,
		},
		{
			ResourceType:         resource.Credential.String(),
			Pkg:                  "credentials",
			StdActions:           []string{"create", "update"},
			SubActionPrefix:      "ssh_private_key",
			HasExtraCommandVars:  true,
			SkipNormalHelp:       true,
			HasExtraHelpFunc:     true,
			HasId:                true,
			HasName:              true,
			HasDescription:       true,
			Container:            "CredentialStore",
			VersionedActions:     []string{"update"},
			NeedsSubtypeInCreate: true,
			PrefixAttributeFieldErrorsWithSubactionPrefix: true,
		},
		{
			ResourceType:         resource.Credential.String(),
			Pkg:                  "credentials",
			StdActions:           []string{"create", "update"},
			SubActionPrefix:      "json",
			SkipNormalHelp:       true,
			HasExtraHelpFunc:     true,
			HasId:                true,
			HasName:              true,
			HasDescription:       true,
			Container:            "CredentialStore",
			VersionedActions:     []string{"update"},
			NeedsSubtypeInCreate: true,
			PrefixAttributeFieldErrorsWithSubactionPrefix: true,
			HasJsonObject: true,
		},
	},
	"groups": {
		{
			ResourceType:        resource.Group.String(),
			Pkg:                 "groups",
			StdActions:          []string{"create", "read", "update", "delete", "list"},
			HasExtraCommandVars: true,
			HasExtraHelpFunc:    true,
			HasId:               true,
			Container:           "Scope",
			HasName:             true,
			HasDescription:      true,
			VersionedActions:    []string{"update", "add-members", "remove-members", "set-members"},
		},
	},
	"hostcatalogs": {
		{
			ResourceType:     resource.HostCatalog.String(),
			Pkg:              "hostcatalogs",
			StdActions:       []string{"read", "delete", "list"},
			HasExtraHelpFunc: true,
			Container:        "Scope",
			HasId:            true,
		},
		{
			ResourceType:         resource.HostCatalog.String(),
			Pkg:                  "hostcatalogs",
			StdActions:           []string{"create", "update"},
			SubActionPrefix:      "static",
			SkipNormalHelp:       true,
			HasExtraHelpFunc:     true,
			HasId:                true,
			HasName:              true,
			HasDescription:       true,
			Container:            "Scope",
			VersionedActions:     []string{"update"},
			NeedsSubtypeInCreate: true,
		},
		{
			ResourceType:         resource.HostCatalog.String(),
			Pkg:                  "hostcatalogs",
			StdActions:           []string{"create", "update"},
			SubActionPrefix:      "plugin",
			SkipNormalHelp:       true,
			HasExtraHelpFunc:     true,
			HasExtraCommandVars:  true,
			HasId:                true,
			HasName:              true,
			HasDescription:       true,
			Container:            "Scope",
			IsPluginType:         true,
			VersionedActions:     []string{"update"},
			NeedsSubtypeInCreate: true,
			HasGenericAttributes: true,
			HasGenericSecrets:    true,
		},
	},
	"hostsets": {
		{
			ResourceType:        resource.HostSet.String(),
			Pkg:                 "hostsets",
			StdActions:          []string{"read", "delete", "list"},
			HasExtraCommandVars: true,
			HasExtraHelpFunc:    true,
			Container:           "HostCatalog",
			HasId:               true,
			HasName:             true,
			HasDescription:      true,
			VersionedActions:    []string{"add-hosts", "set-hosts", "remove-hosts"},
		},
		{
			ResourceType:     resource.HostSet.String(),
			Pkg:              "hostsets",
			StdActions:       []string{"create", "update"},
			SubActionPrefix:  "static",
			SkipNormalHelp:   true,
			HasExtraHelpFunc: true,
			HasId:            true,
			HasName:          true,
			Container:        "HostCatalog",
			HasDescription:   true,
			VersionedActions: []string{"update"},
		},
		{
			ResourceType:         resource.HostSet.String(),
			Pkg:                  "hostsets",
			StdActions:           []string{"create", "update"},
			SubActionPrefix:      "plugin",
			HasExtraCommandVars:  true,
			SkipNormalHelp:       true,
			HasExtraHelpFunc:     true,
			HasId:                true,
			HasName:              true,
			Container:            "HostCatalog",
			HasDescription:       true,
			HasGenericAttributes: true,
			VersionedActions:     []string{"update"},
		},
	},
	"hosts": {
		{
			ResourceType:     resource.Host.String(),
			Pkg:              "hosts",
			StdActions:       []string{"read", "delete", "list"},
			HasExtraHelpFunc: true,
			Container:        "HostCatalog",
			HasId:            true,
			HasName:          true,
			HasDescription:   true,
		},
		{
			ResourceType:        resource.Host.String(),
			Pkg:                 "hosts",
			StdActions:          []string{"create", "update"},
			SubActionPrefix:     "static",
			HasExtraCommandVars: true,
			SkipNormalHelp:      true,
			HasExtraHelpFunc:    true,
			HasId:               true,
			HasName:             true,
			Container:           "HostCatalog",
			HasDescription:      true,
			VersionedActions:    []string{"update"},
		},
	},
	"managedgroups": {
		{
			ResourceType:   resource.ManagedGroup.String(),
			Pkg:            "managedgroups",
			StdActions:     []string{"read", "delete", "list"},
			Container:      "AuthMethod",
			HasId:          true,
			HasName:        true,
			HasDescription: true,
		},
		{
			ResourceType:        resource.ManagedGroup.String(),
			Pkg:                 "managedgroups",
			StdActions:          []string{"create", "update"},
			SubActionPrefix:     "oidc",
			HasExtraCommandVars: true,
			SkipNormalHelp:      true,
			HasExtraHelpFunc:    true,
			HasId:               true,
			HasName:             true,
			Container:           "AuthMethod",
			HasDescription:      true,
			VersionedActions:    []string{"update"},
		},
		{
			ResourceType:        resource.ManagedGroup.String(),
			Pkg:                 "managedgroups",
			StdActions:          []string{"create", "update"},
			SubActionPrefix:     "ldap",
			HasExtraCommandVars: true,
			SkipNormalHelp:      true,
			HasExtraHelpFunc:    true,
			HasId:               true,
			HasName:             true,
			Container:           "AuthMethod",
			HasDescription:      true,
			VersionedActions:    []string{"update"},
		},
	},
	"policies": {
		{
			ResourceType:     resource.Policy.String(),
			Pkg:              "policies",
			StdActions:       []string{"read", "delete", "list"},
			HasExtraHelpFunc: true,
			HasName:          true,
			HasDescription:   true,
			Container:        "Scope",
		},
		{
			ResourceType:         resource.Policy.String(),
			Pkg:                  "policies",
			StdActions:           []string{"create", "update"},
			SubActionPrefix:      "storage",
			HasExtraCommandVars:  true,
			SkipNormalHelp:       true,
			HasExtraHelpFunc:     true,
			HasId:                true,
			HasName:              true,
			Container:            "Scope",
			HasDescription:       true,
			VersionedActions:     []string{"update"},
			NeedsSubtypeInCreate: true,
		},
	},
	"roles": {
		{
			ResourceType:        resource.Role.String(),
			Pkg:                 "roles",
			StdActions:          []string{"create", "read", "update", "delete", "list"},
			HasExtraCommandVars: true,
			HasExtraHelpFunc:    true,
			HasId:               true,
			Container:           "Scope",
			HasName:             true,
			HasDescription:      true,
			VersionedActions:    []string{"update", "add-grants", "remove-grants", "set-grants", "add-principals", "remove-principals", "set-principals", "add-grant-scopes", "remove-grant-scopes", "set-grant-scopes"},
		},
	},
	"scopes": {
		{
			ResourceType:        resource.Scope.String(),
			Pkg:                 "scopes",
			StdActions:          []string{"create", "read", "update", "delete", "list"},
			HasExtraCommandVars: true,
			HasExtraHelpFunc:    true,
			HasId:               true,
			Container:           "Scope",
			HasName:             true,
			HasDescription:      true,
			VersionedActions:    []string{"update", "attach-storage-policy", "detach-storage-policy"},
		},
	},
	"sessions": {
		{
			ResourceType:        resource.Session.String(),
			Pkg:                 "sessions",
			StdActions:          []string{"read", "list"},
			Container:           "Scope",
			HasExtraCommandVars: true,
			HasExtraHelpFunc:    true,
			HasId:               true,
			VersionedActions:    []string{"cancel"},
		},
	},
	"sessionrecordings": {
		{
			ResourceType:        resource.SessionRecording.String(),
			Pkg:                 "sessionrecordings",
			StdActions:          []string{"delete", "read", "list"},
			Container:           "Scope",
			HasExtraCommandVars: true,
			HasExtraHelpFunc:    true,
			HasId:               true,
			SkipFiltering:       true,
		},
	},
	"storagebuckets": {
		{
			ResourceType:         resource.StorageBucket.String(),
			Pkg:                  "storagebuckets",
			StdActions:           []string{"create", "update", "read", "delete", "list"},
			HasExtraHelpFunc:     true,
			HasExtraCommandVars:  true,
			HasId:                true,
			HasName:              true,
			HasDescription:       true,
			Container:            "Scope",
			IsPluginType:         true,
			VersionedActions:     []string{"update"},
			HasGenericAttributes: true,
			HasGenericSecrets:    true,
		},
	},
	"targets": {
		{
			ResourceType:               resource.Target.String(),
			Pkg:                        "targets",
			StdActions:                 []string{"read", "delete", "list"},
			HasExtraCommandVars:        true,
			HasExtraHelpFunc:           true,
			HasExampleCliOutput:        true,
			HasName:                    true,
			HasDescription:             true,
			Container:                  "Scope",
			VersionedActions:           []string{"add-host-sources", "remove-host-sources", "set-host-sources", "add-credential-sources", "remove-credential-sources", "set-credential-sources"},
			UsesAlias:                  true,
			AliasFieldFlag:             "FlagId",
			FlagNameOverwrittenByAlias: "id",
		},
		{
			ResourceType:               resource.Target.String(),
			Pkg:                        "targets",
			StdActions:                 []string{"create", "update"},
			SubActionPrefix:            "tcp",
			HasExtraCommandVars:        true,
			SkipNormalHelp:             true,
			HasExtraHelpFunc:           true,
			HasId:                      true,
			HasName:                    true,
			Container:                  "Scope",
			HasDescription:             true,
			VersionedActions:           []string{"update"},
			NeedsSubtypeInCreate:       true,
			UsesAlias:                  true,
			AliasFieldFlag:             "FlagId",
			FlagNameOverwrittenByAlias: "id",
		},
		{
			ResourceType:               resource.Target.String(),
			Pkg:                        "targets",
			StdActions:                 []string{"create", "update"},
			SubActionPrefix:            "ssh",
			HasExtraCommandVars:        true,
			SkipNormalHelp:             true,
			HasExtraHelpFunc:           true,
			HasId:                      true,
			HasName:                    true,
			Container:                  "Scope",
			HasDescription:             true,
			VersionedActions:           []string{"update"},
			NeedsSubtypeInCreate:       true,
			UsesAlias:                  true,
			AliasFieldFlag:             "FlagId",
			FlagNameOverwrittenByAlias: "id",
		},
		{
			ResourceType:               resource.Target.String(),
			Pkg:                        "targets",
			StdActions:                 []string{"create", "update"},
			SubActionPrefix:            "rdp",
			HasExtraCommandVars:        true,
			SkipNormalHelp:             true,
			HasExtraHelpFunc:           true,
			HasId:                      true,
			HasName:                    true,
			Container:                  "Scope",
			HasDescription:             true,
			VersionedActions:           []string{"update"},
			NeedsSubtypeInCreate:       true,
			UsesAlias:                  true,
			AliasFieldFlag:             "FlagId",
			FlagNameOverwrittenByAlias: "id",
		},
	},
	"users": {
		{
			ResourceType:        resource.User.String(),
			Pkg:                 "users",
			StdActions:          []string{"create", "read", "update", "delete", "list"},
			HasExtraCommandVars: true,
			HasExtraHelpFunc:    true,
			HasId:               true,
			Container:           "Scope",
			HasName:             true,
			HasDescription:      true,
			VersionedActions:    []string{"update", "add-accounts", "remove-accounts", "set-accounts"},
		},
	},
	"workers": {
		{
			ResourceType:     resource.Worker.String(),
			Pkg:              "workers",
			StdActions:       []string{"read", "update", "delete", "list"},
			HasExtraHelpFunc: true,
			HasId:            true,
			Container:        "Scope",
			HasName:          true,
			HasDescription:   true,
			VersionedActions: []string{"update", "add-worker-tags", "set-worker-tags", "remove-worker-tags"},
		},
		{
			ResourceType:          resource.Worker.String(),
			Pkg:                   "workers",
			StdActions:            []string{"create"},
			SubActionPrefix:       "worker-led",
			HasExtraCommandVars:   true,
			SkipNormalHelp:        true,
			HasExtraHelpFunc:      true,
			HasId:                 true,
			HasName:               true,
			Container:             "Scope",
			HasDescription:        true,
			NeedsSubtypeInCreate:  true,
			SkipClientCallActions: []string{"create"},
		},
		{
			ResourceType:          resource.Worker.String(),
			Pkg:                   "workers",
			StdActions:            []string{"create"},
			SubActionPrefix:       "controller-led",
			SkipNormalHelp:        true,
			HasExtraHelpFunc:      true,
			HasId:                 true,
			HasName:               true,
			Container:             "Scope",
			HasDescription:        true,
			NeedsSubtypeInCreate:  true,
			SkipClientCallActions: []string{"create"},
		},
	},
}
