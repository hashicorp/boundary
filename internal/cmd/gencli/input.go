package main

import (
	"github.com/hashicorp/boundary/internal/types/resource"
)

var standardActions = map[string][]string{
	"read":   {"id"},
	"delete": {"id"},
	"list":   {"scope-id"},
}

type cmdInfo struct {
	// The type of the resource, e.g. "target"
	ResourceType string

	// The import path of the API package
	PkgPath string

	// Standard actions (with standard parameters) used by this resource
	StdActions []string

	// HasExtraCommandVars controls whether to generate an embedded struct with
	// extra command variables
	HasExtraCommandVars bool

	// HasExtraSynopsisFunc controls whether to generate code to look for an
	// extra synopsis function
	HasExtraSynopsisFunc bool

	// HasExtraActions controls whether to generate code to populate extra
	// flags into the map and switch on those functions
	HasExtraActions bool

	// HasExtraFlagsFunc controls whether to insert code to add extra flags into
	// the map
	HasExtraFlagsFunc bool

	// HasExtraHelpFunc controls whether to include a default statement chaining
	// to an extra help function
	HasExtraHelpFunc bool

	// HasExampleCliOutput controls whether to generate code to look for a CLI
	// output env var and print
	HasExampleCliOutput bool

	// IsSubtype indicates whether it is a resource type that isn't at the
	// scope, e.g. a host-set, host, or account
	IsSubtype bool

	// IsAbstractType triggers some behavior specialized for abstract types,
	// e.g. those that have subcommands for create/update
	IsAbstractType bool

	// HasFlagHandlingFunc controls whether to call out to an external command
	// for extra flag handling
	HasFlagHandlingFunc bool

	// HasId controls whether to add ID emptiness checking. Note that some
	// commands that allow name/scope id or name/scope name handling may skip
	// this in favor of custom logic.
	HasId bool

	// HasName controls whether to add name options
	HasName bool

	// HasDescription controls whether to add description options
	HasDescription bool

	// HasScopeName controls whether to add scope name options
	HasScopeName bool

	// VersionedActions controls which actions to add a case for version checking
	VersionedActions []string

	// HasExtraActionsOutput controls whether to generate code to call a
	// function for custom output
	HasExtraActionsOutput bool
}

var inputStructs = map[string]*cmdInfo{
	"targets": {
		ResourceType:          resource.Target.String(),
		PkgPath:               "github.com/hashicorp/boundary/api/targets",
		StdActions:            []string{"read", "delete", "list"},
		HasExtraCommandVars:   true,
		HasExtraSynopsisFunc:  true,
		HasExtraActions:       true,
		HasExtraFlagsFunc:     true,
		HasExtraHelpFunc:      true,
		HasExampleCliOutput:   true,
		IsAbstractType:        true,
		HasFlagHandlingFunc:   true,
		HasName:               true,
		HasDescription:        true,
		VersionedActions:      []string{"add-host-sets", "remove-host-sets", "set-host-sets"},
		HasExtraActionsOutput: true,
	},
}
