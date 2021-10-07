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

	// IsAbstractType triggers some behavior specialized for abstract types,
	// e.g. those that have subcommands for create/update
	IsAbstractType bool

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

	// IsPluginType controls whether standard plugin flags are generated
	IsPluginType bool
}

var inputStructs = map[string][]*cmdInfo{
	"accounts": {
		{
			ResourceType:        resource.Account.String(),
			Pkg:                 "accounts",
			StdActions:          []string{"read", "delete", "list"},
			HasExtraCommandVars: true,
			HasExtraHelpFunc:    true,
			IsAbstractType:      true,
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
	},
	"authmethods": {
		{
			ResourceType:     resource.AuthMethod.String(),
			Pkg:              "authmethods",
			StdActions:       []string{"read", "delete", "list"},
			IsAbstractType:   true,
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
	},
	"authtokens": {
		{
			ResourceType: resource.AuthToken.String(),
			Pkg:          "authtokens",
			StdActions:   []string{"read", "delete", "list"},
			Container:    "Scope",
		},
	},
	"credentialstores": {
		{
			ResourceType:     resource.CredentialStore.String(),
			Pkg:              "credentialstores",
			StdActions:       []string{"read", "delete", "list"},
			IsAbstractType:   true,
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
	},
	"credentiallibraries": {
		{
			ResourceType:     resource.CredentialLibrary.String(),
			Pkg:              "credentiallibraries",
			StdActions:       []string{"read", "delete", "list"},
			IsAbstractType:   true,
			HasExtraHelpFunc: true,
			Container:        "CredentialStore",
			HasId:            true,
		},
		{
			ResourceType:        resource.CredentialLibrary.String(),
			Pkg:                 "credentiallibraries",
			StdActions:          []string{"create", "update"},
			SubActionPrefix:     "vault",
			HasExtraCommandVars: true,
			SkipNormalHelp:      true,
			HasExtraHelpFunc:    true,
			HasId:               true,
			HasName:             true,
			HasDescription:      true,
			Container:           "CredentialStore",
			VersionedActions:    []string{"update"},
			PrefixAttributeFieldErrorsWithSubactionPrefix: true,
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
			IsAbstractType:   true,
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
	},
	"hostsets": {
		{
			ResourceType:        resource.HostSet.String(),
			Pkg:                 "hostsets",
			StdActions:          []string{"read", "delete", "list"},
			HasExtraCommandVars: true,
			HasExtraHelpFunc:    true,
			IsAbstractType:      true,
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
	},
	"hosts": {
		{
			ResourceType:     resource.Host.String(),
			Pkg:              "hosts",
			StdActions:       []string{"read", "delete", "list"},
			HasExtraHelpFunc: true,
			IsAbstractType:   true,
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
			IsAbstractType: true,
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
			VersionedActions:    []string{"update", "add-grants", "remove-grants", "set-grants", "add-principals", "remove-principals", "set-principals"},
		},
	},
	"scopes": {
		{
			ResourceType:        resource.Scope.String(),
			Pkg:                 "scopes",
			StdActions:          []string{"create", "read", "update", "delete", "list"},
			HasExtraCommandVars: true,
			HasId:               true,
			Container:           "Scope",
			HasName:             true,
			HasDescription:      true,
			VersionedActions:    []string{"update"},
		},
	},
	"sessions": {
		{
			ResourceType:     resource.Session.String(),
			Pkg:              "sessions",
			StdActions:       []string{"read", "list"},
			Container:        "Scope",
			HasExtraHelpFunc: true,
			HasId:            true,
			VersionedActions: []string{"cancel"},
		},
	},
	"targets": {
		{
			ResourceType:        resource.Target.String(),
			Pkg:                 "targets",
			StdActions:          []string{"read", "delete", "list"},
			HasExtraCommandVars: true,
			HasExtraHelpFunc:    true,
			HasExampleCliOutput: true,
			IsAbstractType:      true,
			HasName:             true,
			HasDescription:      true,
			Container:           "Scope",
			VersionedActions:    []string{"add-host-sets", "remove-host-sets", "set-host-sets", "add-host-sources", "remove-host-sources", "set-host-sources", "add-credential-libraries", "remove-credential-libraries", "set-credential-libraries", "add-credential-sources", "remove-credential-sources", "set-credential-sources"},
		},
		{
			ResourceType:         resource.Target.String(),
			Pkg:                  "targets",
			StdActions:           []string{"create", "update"},
			SubActionPrefix:      "tcp",
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
}
