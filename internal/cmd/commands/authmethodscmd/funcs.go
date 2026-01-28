// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package authmethodscmd

import (
	"fmt"
	"sort"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func init() {
	extraOidcSynopsisFunc = extraSynopsisFuncImpl
}

func (c *Command) extraHelpFunc(helpMap map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "":
		return base.WrapForHelpText([]string{
			"Usage: boundary auth-methods [sub command] [options] [args]",
			"",
			"  This command allows operations on Boundary auth method resources. Example:",
			"",
			"    Read an auth method:",
			"",
			`      $ boundary auth-methods read -id ampw_1234567890`,
			"",
			"  Please see the auth-methods subcommand help for detailed usage information.",
		})
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary auth-methods create [type] [sub command] [options] [args]",
			"",
			"  This command allows create operations on Boundary auth method resources. Example:",
			"",
			"    Create a password-type auth method:",
			"",
			`      $ boundary auth-methods create password -name prodops -description "For ProdOps usage"`,
			"",
			"  Please see the typed subcommand help for detailed usage information.",
		})
	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary auth-methods update [type] [sub command] [options] [args]",
			"",
			"  This command allows update operations on Boundary auth method resources. Example:",
			"",
			"    Update a password-type auth method:",
			"",
			`      $ boundary auth-methods update password -id ampw_1234567890 -name devops -description "For DevOps usage"`,
			"",
			"  Please see the typed subcommand help for detailed usage information.",
		})
	}
	return helpStr + c.Flags().Help()
}

func extraSynopsisFuncImpl(c *OidcCommand) string {
	switch c.Func {
	case "change-state":
		return "Change the active state of an auth method"

	default:
		return ""
	}
}

func (c *Command) printListTable(items []*authmethods.AuthMethod) string {
	if len(items) == 0 {
		return "No auth methods found"
	}

	var output []string
	output = []string{
		"",
		"Auth Method information:",
	}
	for i, item := range items {
		if i > 0 {
			output = append(output, "")
		}
		if item.Id != "" {
			output = append(output,
				fmt.Sprintf("  ID:                     %s", item.Id),
			)
		} else {
			output = append(output,
				fmt.Sprintf("  ID:                     %s", "(not available)"),
			)
		}
		if c.FlagRecursive && item.ScopeId != "" {
			output = append(output,
				fmt.Sprintf("    Scope ID:             %s", item.ScopeId),
			)
		}
		if item.Version > 0 {
			output = append(output,
				fmt.Sprintf("    Version:              %d", item.Version),
			)
		}
		if item.Type != "" {
			output = append(output,
				fmt.Sprintf("    Type:                 %s", item.Type),
			)
		}
		if item.Name != "" {
			output = append(output,
				fmt.Sprintf("    Name:                 %s", item.Name),
			)
		}
		if item.Description != "" {
			output = append(output,
				fmt.Sprintf("    Description:          %s", item.Description),
			)
		}
		if item.IsPrimary {
			output = append(output,
				fmt.Sprintf("    Is Primary For Scope: %t", item.IsPrimary),
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

func printItemTable(item *authmethods.AuthMethod, resp *api.Response) string {
	nonAttributeMap := map[string]any{}
	if item.Id != "" {
		nonAttributeMap["ID"] = item.Id
	}
	if item.Version != 0 {
		nonAttributeMap["Version"] = item.Version
	}
	if item.Type != "" {
		nonAttributeMap["Type"] = item.Type
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
	if resp != nil && resp.Map != nil {
		if resp.Map[globals.IsPrimaryField] != nil {
			nonAttributeMap["Is Primary For Scope"] = item.IsPrimary
		}
	}

	maxLength := base.MaxAttributesLength(nonAttributeMap, item.Attributes, keySubstMap)

	ret := []string{
		"",
		"Auth Method information:",
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

	if len(item.AuthorizedCollectionActions) > 0 {
		keys := make([]string, 0, len(item.AuthorizedCollectionActions))
		for k := range item.AuthorizedCollectionActions {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		ret = append(ret,
			"",
			"  Authorized Actions on Auth Method's Collections:",
		)
		for _, key := range keys {
			ret = append(ret,
				fmt.Sprintf("    %s:", key),
				base.WrapSlice(6, item.AuthorizedCollectionActions[key]),
			)
		}
	}

	if len(item.Attributes) > 0 {
		ret = append(ret,
			"",
			"  Attributes:",
			base.WrapMap(4, maxLength, item.Attributes),
		)
	}

	return base.WrapForHelpText(ret)
}

var keySubstMap = map[string]string{
	"min_login_name_length": "Minimum Login Name Length",
	"min_password_length":   "Minimum Password Length",
}
