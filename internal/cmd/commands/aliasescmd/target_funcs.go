// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package aliasescmd

import (
	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/aliases"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func init() {
	extraTargetActionsFlagsMapFunc = extraTargetActionsFlagsMapFuncImpl
	extraTargetFlagsFunc = extraTargetFlagsFuncImpl
	extraTargetFlagsHandlingFunc = extraTargetFlagHandlingFuncImpl
	executeExtraTargetActions = executeExtraTargetActionsImpl
}

type extraTargetCmdVars struct {
	flagValue                  string
	flagDestinationId          string
	flagAuthorizeSessionHostId string
}

func extraTargetActionsFlagsMapFuncImpl() map[string][]string {
	return map[string][]string{
		"create": {"value", "destination-id", "authorize-session-host-id"},
		"update": {"value", "destination-id", "authorize-session-host-id"},
	}
}

func (c *TargetCommand) extraTargetHelpFunc(helpMap map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "":
		return base.WrapForHelpText([]string{
			"Usage: boundary aliases [sub command] [options] [args]",
			"",
			"  This command allows operations on Boundary alias resources. Example:",
			"",
			"    Read an alias:",
			"",
			`      $ boundary aliases read -id alt_1234567890`,
			"",
			"  Please see the aliases subcommand help for detailed usage information.",
		})
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary aliases create target [options] [args]",
			"",
			"  Create a target-type alias. Example:",
			"",
			`    $ boundary aliases create target -value prod-ops.example -name prodops -description "Target alias for ProdOps"`,
			"",
			"",
		})
	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary aliases update target [options] [args]",
			"",
			"  Update an alias. Example:",
			"",
			`    $ boundary aliases update target -id alt_1234567890 -name devops`,
			"",
			"",
		})
	}
	return helpStr + c.Flags().Help()
}

func extraTargetFlagsFuncImpl(c *TargetCommand, set *base.FlagSets, f *base.FlagSet) {
	for _, name := range flagsTargetMap[c.Func] {
		switch name {
		case "value":
			f.StringVar(&base.StringVar{
				Name:   "value",
				Target: &c.flagValue,
				Usage:  "The value of the alias",
			})
		case "destination-id":
			f.StringVar(&base.StringVar{
				Name:   "destination-id",
				Target: &c.flagDestinationId,
				Usage:  "The target id that the alias points to.",
			})
		}
	}

	f = set.NewFlagSet("Target Alias Options")
	for _, name := range flagsTargetMap[c.Func] {
		switch name {
		case "authorize-session-host-id":
			f.StringVar(&base.StringVar{
				Name:   "authorize-session-host-id",
				Target: &c.flagAuthorizeSessionHostId,
				Usage:  "The host id to pass in when authorizing a session with this alias.",
			})
		}
	}
}

func extraTargetFlagHandlingFuncImpl(c *TargetCommand, _ *base.FlagSets, opts *[]aliases.Option) bool {
	var attributes map[string]any
	addAttribute := func(name string, value any) {
		if attributes == nil {
			attributes = make(map[string]any)
		}
		attributes[name] = value
	}

	switch c.flagDestinationId {
	case "":
	case "null":
		*opts = append(*opts, aliases.DefaultDestinationId())
	default:
		*opts = append(*opts, aliases.WithDestinationId(c.flagDestinationId))
	}

	switch c.flagAuthorizeSessionHostId {
	case "":
	case "null":
		addAttribute("authorize_session_arguments", nil)
	default:
		asa := aliases.AuthorizeSessionArguments{HostId: c.flagAuthorizeSessionHostId}
		addAttribute("authorize_session_arguments", asa)
	}

	if attributes != nil {
		*opts = append(*opts, aliases.WithAttributes(attributes))
	}

	return true
}

func executeExtraTargetActionsImpl(c *TargetCommand, inResp *api.Response, inItem *aliases.Alias, inErr error, aliasesClient *aliases.Client, version uint32, opts []aliases.Option) (*api.Response, *aliases.Alias, error) {
	switch c.Func {
	case "create":
		// we specify our own create action here because we have more required
		// fields in the sdk than is specified in the templates for all the other
		// resources.
		createResult, err := aliasesClient.Create(c.Context, "target", c.flagValue, c.FlagScopeId, opts...)
		if err != nil {
			return nil, nil, err
		}
		return createResult.GetResponse(), createResult.GetItem(), nil
	}
	return inResp, inItem, inErr
}
