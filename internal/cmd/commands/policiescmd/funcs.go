// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package policiescmd

import (
	"fmt"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/policies"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

var keySubstMap = map[string]string{
	"retain_for":   "Storage Retention",
	"delete_after": "Storage Deletion",
	"days":         "Days",
	"overridable":  "Overridable",
}

func (c *Command) extraHelpFunc(_ map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "":
		return base.WrapForHelpText([]string{
			"Usage: boundary policies [sub command] [options] [args]",
			"",
			"  This command allows operations on Boundary policy resources. Example:",
			"",
			"    Read a policy:",
			"",
			`      $ boundary policies read -id pst_1234567890`,
			"",
			"  Please see the subcommand help for detailed usage information.",
		})
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary policies create [type] [sub command] [options] [args]",
			"",
			"  This command allows create operations on Boundary policy resources. Example:",
			"",
			"    Create a storage-type policy:",
			"",
			`      $ boundary policies create storage -name prod -description "Prod Storage Policy" -retain-for-days 10 -delete-after-days 20`,
			"",
			"  Please see the typed subcommand help for detailed usage information.",
		})
	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary policies update [type] [sub command] [options] [args]",
			"",
			"  This command allows update operations on Boundary policy resources. Example:",
			"",
			"    Update a storage-type policy:",
			"",
			`      $ boundary policies update storage -id pst_1234567890 -name dev -description "Dev Storage Policy" -retain-for-days 1 -delete-after-days 2`,
			"",
			"  Please see the typed subcommand help for detailed usage information.",
		})
	}

	return helpStr + c.Flags().Help()
}

func (c *Command) printListTable(items []*policies.Policy) string {
	if len(items) == 0 {
		return "No policies found"
	}
	var output []string
	output = []string{
		"",
		"Policy information:",
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
		if item.Type != "" {
			output = append(output,
				fmt.Sprintf("    Type:                %s", item.Type),
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

func printItemTable(item *policies.Policy, _ *api.Response) string {
	nonAttributeMap := map[string]any{}
	if item.Id != "" {
		nonAttributeMap["ID"] = item.Id
	}
	if item.Name != "" {
		nonAttributeMap["Name"] = item.Name
	}
	if item.Description != "" {
		nonAttributeMap["Description"] = item.Description
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

	// MaxAttributesLength replaces attribute map keys with their human-readable
	// names. In the case of policies, some attributes might in themselves be
	// objects, so we search inside the attributes and re-run.
	maxLength := base.MaxAttributesLength(nonAttributeMap, item.Attributes, keySubstMap)
	for _, v := range item.Attributes {
		if m, ok := v.(map[string]any); ok {
			ml := base.MaxAttributesLength(nonAttributeMap, m, keySubstMap)
			if ml > maxLength {
				maxLength = ml
			}
		}
	}

	ret := []string{
		"",
		"Policy information:",
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

	ret = append(ret,
		"",
	)

	switch item.Type {
	// For storage-type policies, we have optional objects with optional values
	// inside the attributes map, so we have to look in the attributes to print.
	case "storage":
		if len(item.Attributes) > 0 {
			ret = append(ret, "  Attributes:")
			// MaxAttributesLength substitutes the JSON keys in the map for the
			// named ones, so look in the key substring map for them instead of
			// using the JSON name.
			retainFor, ok := item.Attributes[keySubstMap["retain_for"]]
			if ok && len(retainFor.(map[string]any)) > 0 {
				ret = append(ret,
					fmt.Sprintf("    %s:", keySubstMap["retain_for"]),
					base.WrapMap(6, maxLength, retainFor.(map[string]any)),
					"",
				)
			}
			deleteAfter, ok := item.Attributes[keySubstMap["delete_after"]]
			if ok && len(deleteAfter.(map[string]any)) > 0 {
				ret = append(ret,
					fmt.Sprintf("    %s:", keySubstMap["delete_after"]),
					base.WrapMap(6, maxLength, deleteAfter.(map[string]any)),
					"",
				)
			}
		}

	default:
		if len(item.Attributes) > 0 {
			ret = append(ret,
				"  Attributes:",
				base.WrapMap(4, maxLength, item.Attributes),
			)
		}
	}

	return base.WrapForHelpText(ret)
}
