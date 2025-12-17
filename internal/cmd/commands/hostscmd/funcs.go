// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package hostscmd

import (
	"fmt"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/hosts"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func (c *Command) extraHelpFunc(helpMap map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "":
		return base.WrapForHelpText([]string{
			"Usage: boundary hosts [sub command] [options] [args]",
			"",
			"  This command allows operations on Boundary host resources. Example:",
			"",
			"    Read a host:",
			"",
			`      $ boundary hosts read -id hst_1234567890`,
			"",
			"  Please see the hosts subcommand help for detailed usage information.",
		})
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary hosts create [type] [sub command] [options] [args]",
			"",
			"  This command allows create operations on Boundary host resources. Example:",
			"",
			"    Create a static-type host:",
			"",
			`      $ boundary hosts create static -name prodops -description "For ProdOps usage"`,
			"",
			"  Please see the typed subcommand help for detailed usage information.",
		})
	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary hosts update [type] [sub command] [options] [args]",
			"",
			"  This command allows update operations on Boundary host resources. Example:",
			"",
			"    Update a static-type host:",
			"",
			`      $ boundary hosts update static -id hst_1234567890 -name devops -description "For DevOps usage"`,
			"",
			"  Please see the typed subcommand help for detailed usage information.",
		})
	default:
		helpStr = helpMap[c.Func]()
	}
	return helpStr + c.Flags().Help()
}

func (c *Command) printListTable(items []*hosts.Host) string {
	if len(items) == 0 {
		return "No hosts found"
	}

	var output []string
	output = []string{
		"",
		"Host information:",
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
		if item.ExternalId != "" {
			output = append(output,
				fmt.Sprintf("    External ID:         %s", item.ExternalId),
			)
		}
		if item.ExternalName != "" {
			output = append(output,
				fmt.Sprintf("    External Name:       %s", item.ExternalName),
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

func printItemTable(item *hosts.Host, resp *api.Response) string {
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
	if item.HostCatalogId != "" {
		nonAttributeMap["Host Catalog ID"] = item.HostCatalogId
	}
	if item.ExternalId != "" {
		nonAttributeMap["External ID"] = item.ExternalId
	}
	if item.ExternalName != "" {
		nonAttributeMap["External Name"] = item.ExternalName
	}

	maxLength := base.MaxAttributesLength(nonAttributeMap, item.Attributes, keySubstMap)

	ret := []string{
		"",
		"Host information:",
		base.WrapMap(2, maxLength+2, nonAttributeMap),
	}

	if item.Scope != nil {
		ret = append(ret,
			"",
			"  Scope:",
			base.ScopeInfoForOutput(item.Scope, maxLength),
		)
	}

	if item.Plugin != nil {
		ret = append(ret,
			"",
			"  Plugin:",
			base.PluginInfoForOutput(item.Plugin, maxLength),
		)
	}

	if len(item.AuthorizedActions) > 0 {
		ret = append(ret,
			"",
			"  Authorized Actions:",
			base.WrapSlice(4, item.AuthorizedActions),
		)
	}

	if len(item.HostSetIds) > 0 {
		ret = append(ret,
			"",
			"  Host Set IDs:",
			base.WrapSlice(4, item.HostSetIds),
		)
	}

	if len(item.IpAddresses) > 0 {
		ret = append(ret,
			"",
			"  IP Addresses:",
			base.WrapSlice(4, item.IpAddresses),
		)
	}

	if len(item.DnsNames) > 0 {
		ret = append(ret,
			"",
			"  DNS Names:",
			base.WrapSlice(4, item.DnsNames),
		)
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

var keySubstMap = map[string]string{}
