// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package aliasescmd

import (
	"fmt"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/aliases"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func (c *Command) extraHelpFunc(helpMap map[string]func() string) string {
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
			"  Create an alias. Example:",
			"",
			`    $ boundary aliases create target -value prod-ops.example -name prodops -description "Target alias for ProdOps"`,
			"",
			"  Please see the typed subcommand help for detailed usage information.",
		})
	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary aliases update target [options] [args]",
			"",
			"  Update an alias. Example:",
			"",
			`    $ boundary aliases update target -id alt_1234567890 -name devops`,
			"",
			"  Please see the typed subcommand help for detailed usage information.",
		})

	default:
		helpStr = ""
	}
	return helpStr + c.Flags().Help()
}

func (c *Command) printListTable(items []*aliases.Alias) string {
	if len(items) == 0 {
		return "No aliases found"
	}
	var output []string
	output = []string{
		"",
		"Alias information:",
	}
	for i, item := range items {
		if i > 0 {
			output = append(output, "")
		}
		if item.Id != "" {
			output = append(output,
				fmt.Sprintf("  ID:               %s", item.Id),
			)
		} else {
			output = append(output,
				fmt.Sprintf("  ID:               %s", "(not available)"),
			)
		}
		if c.FlagRecursive && item.ScopeId != "" {
			output = append(output,
				fmt.Sprintf("    Scope ID:       %s", item.ScopeId),
			)
		}
		if item.Version > 0 {
			output = append(output,
				fmt.Sprintf("    Version:        %d", item.Version),
			)
		}
		if item.Type != "" {
			output = append(output,
				fmt.Sprintf("    Type:           %s", item.Type),
			)
		}
		if item.Name != "" {
			output = append(output,
				fmt.Sprintf("    Name:           %s", item.Name),
			)
		}
		if item.Description != "" {
			output = append(output,
				fmt.Sprintf("    Description:    %s", item.Description),
			)
		}
		if item.Value != "" {
			output = append(output,
				fmt.Sprintf("    Value:          %s", item.Value),
			)
		}
		if item.DestinationId != "" {
			output = append(output,
				fmt.Sprintf("    Destination ID: %s", item.DestinationId),
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

func printItemTable(item *aliases.Alias, resp *api.Response) string {
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
	if item.Value != "" {
		nonAttributeMap["Value"] = item.Value
	}
	if item.DestinationId != "" {
		nonAttributeMap["Destination ID"] = item.DestinationId
	}

	maxLength := base.MaxAttributesLength(nonAttributeMap, nil, nil)

	ret := []string{
		"",
		"Alias information:",
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

	if len(item.Attributes) > 0 {
		ret = append(ret,
			"",
			"  Attributes:",
			// TODO: This looks kind of ugly but it is used across boundary.
			// Revisit the formatting of attributes that have nested maps.
			base.WrapMap(4, maxLength+2, item.Attributes),
		)
	}

	return base.WrapForHelpText(ret)
}
