// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package rolescmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/roles"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/version"
	"github.com/mitchellh/go-wordwrap"
)

func init() {
	extraActionsFlagsMapFunc = extraActionsFlagsMapFuncImpl
	extraSynopsisFunc = extraSynopsisFuncImpl
	extraFlagsFunc = extraFlagsFuncImpl
	extraFlagsHandlingFunc = extraFlagsHandlingFuncImpl
	executeExtraActions = executeExtraActionsImpl
}

type extraCmdVars struct {
	flagGrantScopeId string
	flagPrincipals   []string
	flagGrants       []string
}

func extraActionsFlagsMapFuncImpl() map[string][]string {
	return map[string][]string{
		"create":            {"grant-scope-id"},
		"update":            {"grant-scope-id"},
		"add-principals":    {"id", "principal", "version"},
		"set-principals":    {"id", "principal", "version"},
		"remove-principals": {"id", "principal", "version"},
		"add-grants":        {"id", "grant", "version"},
		"set-grants":        {"id", "grant", "version"},
		"remove-grants":     {"id", "grant", "version"},
	}
}

func extraSynopsisFuncImpl(c *Command) string {
	switch c.Func {
	case "add-principals", "set-principals", "remove-principals":
		return c.principalsGrantsSynopsisFunc(c.Func, true)
	case "add-grants", "set-grants", "remove-grants":
		return c.principalsGrantsSynopsisFunc(c.Func, false)
	}

	return ""
}

func (c *Command) principalsGrantsSynopsisFunc(inFunc string, principals bool) string {
	var in string
	switchStr := "principals (users, groups)"
	if !principals {
		switchStr = "grants"
	}
	switch {
	case strings.HasPrefix(inFunc, "add"):
		in = fmt.Sprintf("Add %s to", switchStr)
	case strings.HasPrefix(inFunc, "set"):
		in = fmt.Sprintf("Set the full contents of the %s on", switchStr)
	case strings.HasPrefix(inFunc, "remove"):
		in = fmt.Sprintf("Remove %s from", switchStr)
	}
	return wordwrap.WrapString(fmt.Sprintf("%s a role", in), base.TermWidth)
}

func (c *Command) extraHelpFunc(helpMap map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "add-principals":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary roles add-principals [options] [args]",
			"",
			`  Adds principals (users, groups) to a role given its ID. The "principal" flag can be specified multiple times. Example:`,
			"",
			`    $ boundary roles add-principals -id r_1234567890 -principal u_1234567890`,
			"",
			"",
		})

	case "set-principals":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary roles set-principals [options] [args]",
			"",
			`  Sets the complete set of principals (users, groups) on a role given its ID. The "principal" flag can be specified multiple times. Example:`,
			"",
			`    $ boundary roles set-principals -id r_1234567890 -principal u_anon -principal sg_1234567890`,
			"",
			"",
		})

	case "remove-principals":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary roles remove-principals [options] [args]",
			"",
			`  Removes principals (users, groups) from a role given its ID. The "principal" flags can be specified multiple times. Example:`,
			"",
			`    $ boundary roles remove-principals -id r_1234567890 -principal sg_1234567890`,
			"",
			"",
		})

	case "add-grants":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary roles add-grants [options] [args]",
			"",
			`  Adds grants to a role given its ID. The "grant" flag can be specified multiple times. Example:`,
			"",
			`    $ boundary roles add-grants -id r_1234567890 -grant "id=*;type=*;actions=read"`,
			"",
			"",
		})

	case "set-grants":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary roles set-grants [options] [args]",
			"",
			`  Sets the complete set of grants on a role given its ID. The "grant" flag can be specified multiple times. Example:`,
			"",
			`    $ boundary roles set-grants -id r_1234567890 -grant "id=*;type=*;actions=read" -grant "id=*;type=*;actions=list"`,
			"",
			"",
		})

	case "remove-grants":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary roles remove-grants [options] [args]",
			"",
			`  Removes grants from a role given its ID. The "grant" flags can be specified multiple times. Example:`,
			"",
			`    $ boundary roles remove-grants -id r_1234567890 -grant "id=*;type=*;actions=read"`,
			"",
			"",
		})

	default:
		helpStr = helpMap["base"]()
	}
	return helpStr + c.Flags().Help()
}

func extraFlagsFuncImpl(c *Command, _ *base.FlagSets, f *base.FlagSet) {
	for _, name := range flagsMap[c.Func] {
		switch name {
		case "grant-scope-id":
			f.StringVar(&base.StringVar{
				Name:   "grant-scope-id",
				Target: &c.flagGrantScopeId,
				Usage:  "The scope ID for grants set on the role",
			})
		case "principal":
			f.StringSliceVar(&base.StringSliceVar{
				Name:   "principal",
				Target: &c.flagPrincipals,
				Usage:  "The principals (users or groups) to add, remove, or set. May be specified multiple times.",
			})
		case "grant":
			f.StringSliceVar(&base.StringSliceVar{
				Name:   "grant",
				Target: &c.flagGrants,
				Usage:  "The grants to add, remove, or set. May be specified multiple times. Can be in compact string format or JSON (be sure to escape JSON properly).",
			})
		}
	}
}

func extraFlagsHandlingFuncImpl(c *Command, _ *base.FlagSets, opts *[]roles.Option) bool {
	switch c.flagGrantScopeId {
	case "":
	case "null":
		*opts = append(*opts, roles.DefaultGrantScopeId())
	default:
		*opts = append(*opts, roles.WithGrantScopeId(c.flagGrantScopeId))
	}

	switch c.Func {
	case "add-principals", "remove-principals":
		if len(c.flagPrincipals) == 0 {
			c.UI.Error("No principals supplied via -principal")
			return false
		}

	case "add-grants", "remove-grants":
		if len(c.flagGrants) == 0 {
			c.UI.Error("No grants supplied via -grant")
			return false
		}

	case "set-principals":
		switch len(c.flagPrincipals) {
		case 0:
			c.UI.Error("No principals supplied via -principal")
			return false
		case 1:
			if c.flagPrincipals[0] == "null" {
				c.flagPrincipals = nil
			}
		}

	case "set-grants":
		switch len(c.flagGrants) {
		case 0:
			c.UI.Error("No grants supplied via -grant")
			return false
		case 1:
			if c.flagGrants[0] == "null" {
				c.flagGrants = nil
			}
		}
	}

	if len(c.flagGrants) > 0 {
		for _, grant := range c.flagGrants {
			parsed, err := perms.Parse(c.Context, scope.Global.String(), grant)
			if err != nil {
				c.UI.Error(fmt.Errorf("Grant %q could not be parsed successfully: %w", grant, err).Error())
				return false
			}
			switch {
			case parsed.Id() == "":
				// Nothing
			case version.SupportsFeature(version.Binary, version.SupportIdInGrants):
				c.UI.Warn(fmt.Sprintf("Grant %q uses the %q field, which is deprecated and will not be allowed in version 0.15.0+. Please use %q instead.", grant, "id", "ids"))
			default:
				c.UI.Error(fmt.Sprintf("Grant %q uses the %q field which is no longer supported. Please use %q instead.", grant, "id", "ids"))
				return false
			}
		}
	}

	return true
}

func executeExtraActionsImpl(c *Command, origResp *api.Response, origItem *roles.Role, origItems []*roles.Role, origError error, roleClient *roles.Client, version uint32, opts []roles.Option) (*api.Response, *roles.Role, []*roles.Role, error) {
	switch c.Func {
	case "add-principals":
		result, err := roleClient.AddPrincipals(c.Context, c.FlagId, version, c.flagPrincipals, opts...)
		if err != nil {
			return nil, nil, nil, err
		}
		return result.GetResponse(), result.GetItem(), nil, err
	case "set-principals":
		result, err := roleClient.SetPrincipals(c.Context, c.FlagId, version, c.flagPrincipals, opts...)
		if err != nil {
			return nil, nil, nil, err
		}
		return result.GetResponse(), result.GetItem(), nil, err
	case "remove-principals":
		result, err := roleClient.RemovePrincipals(c.Context, c.FlagId, version, c.flagPrincipals, opts...)
		if err != nil {
			return nil, nil, nil, err
		}
		return result.GetResponse(), result.GetItem(), nil, err
	case "add-grants":
		result, err := roleClient.AddGrants(c.Context, c.FlagId, version, c.flagGrants, opts...)
		if err != nil {
			return nil, nil, nil, err
		}
		return result.GetResponse(), result.GetItem(), nil, err
	case "set-grants":
		result, err := roleClient.SetGrants(c.Context, c.FlagId, version, c.flagGrants, opts...)
		if err != nil {
			return nil, nil, nil, err
		}
		return result.GetResponse(), result.GetItem(), nil, err
	case "remove-grants":
		result, err := roleClient.RemoveGrants(c.Context, c.FlagId, version, c.flagGrants, opts...)
		if err != nil {
			return nil, nil, nil, err
		}
		return result.GetResponse(), result.GetItem(), nil, err
	}
	return origResp, origItem, origItems, origError
}

func (c *Command) printListTable(items []*roles.Role) string {
	if len(items) == 0 {
		return "No roles found"
	}

	var output []string
	output = []string{
		"",
		"Role information:",
	}
	for i, item := range items {
		if i > 0 {
			output = append(output, "")
		}
		if item.Id != "" {
			output = append(output,
				fmt.Sprintf("  ID:                    %s", item.Id),
			)
		} else {
			output = append(output,
				fmt.Sprintf("  ID:                    %s", "(not available)"),
			)
		}
		if c.FlagRecursive && item.ScopeId != "" {
			output = append(output,
				fmt.Sprintf("    Scope ID:            %s", item.ScopeId),
			)
		}
		if item.Version > 0 {
			output = append(output,
				fmt.Sprintf("    Version:             %d", item.Version),
			)
		}
		if item.Name != "" {
			output = append(output,
				fmt.Sprintf("    Name:                %s", item.Name),
			)
		}
		if item.Description != "" {
			output = append(output,
				fmt.Sprintf("    Description:         %s", item.Description),
			)
		}
		if len(item.AuthorizedActions) > 0 {
			output = append(output,
				"    Authorized Actions:",
				base.WrapSlice(6, item.AuthorizedActions),
			)
		}
	}

	return base.WrapForHelpText(output)
}

func printItemTable(item *roles.Role, resp *api.Response) string {
	nonAttributeMap := map[string]any{}
	if item.Id != "" {
		nonAttributeMap["ID"] = item.Id
	}
	if item.Version != 0 {
		nonAttributeMap["Version"] = item.Version
	}
	if !item.CreatedTime.IsZero() {
		nonAttributeMap["Created Time"] = item.CreatedTime.Local().Format(time.RFC1123)
	}
	if !item.UpdatedTime.IsZero() {
		nonAttributeMap["Updated Time"] = item.UpdatedTime.Local().Format(time.RFC1123)
	}
	if item.Name != "" {
		nonAttributeMap["Name"] = item.Name
	}
	if item.Description != "" {
		nonAttributeMap["Description"] = item.Description
	}
	if item.GrantScopeId != "" {
		nonAttributeMap["Grant Scope ID"] = item.GrantScopeId
	}

	maxLength := base.MaxAttributesLength(nonAttributeMap, nil, nil)

	ret := []string{
		"",
		"Role information:",
		base.WrapMap(2, maxLength+2, nonAttributeMap),
	}

	if item.Scope != nil {
		ret = append(ret,
			"",
			"  Scope:",
			base.ScopeInfoForOutput(item.Scope, maxLength),
		)
	}

	if len(item.AuthorizedActions) > 0 {
		ret = append(ret,
			"",
			"  Authorized Actions:",
			base.WrapSlice(4, item.AuthorizedActions),
		)
	}

	if len(item.Principals) > 0 {
		ret = append(ret,
			"",
			fmt.Sprintf("  Principals:       %s", ""),
		)
	}
	for _, principal := range item.Principals {
		ret = append(ret,
			fmt.Sprintf("    ID:             %s", principal.Id),
			fmt.Sprintf("      Type:         %s", principal.Type),
			fmt.Sprintf("      Scope ID:     %s", principal.ScopeId),
		)
	}
	if len(item.Grants) > 0 {
		ret = append(ret,
			"",
			fmt.Sprintf("  Canonical Grants: %s", ""),
		)
	}
	for _, grant := range item.Grants {
		ret = append(ret,
			fmt.Sprintf("    %s", grant.Canonical),
		)
	}

	return base.WrapForHelpText(ret)
}
