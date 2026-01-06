// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package hostcatalogscmd

import (
	"fmt"
	"sort"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/hostcatalogs"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func (c *Command) extraHelpFunc(helpMap map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "":
		return base.WrapForHelpText([]string{
			"Usage: boundary host-catalogs [sub command] [options] [args]",
			"",
			"  This command allows operations on Boundary host catalog resources. Example:",
			"",
			"    Read a host catalog:",
			"",
			`      $ boundary host-catalogs read -id hcst_1234567890`,
			"",
			"  Please see the host-catalogs subcommand help for detailed usage information.",
		})
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary host-catalogs create [type] [sub command] [options] [args]",
			"",
			"  This command allows create operations on Boundary host catalog resources. Example:",
			"",
			"    Create a static-type host catalog:",
			"",
			`      $ boundary host-catalogs create static -name prodops -description "For ProdOps usage"`,
			"",
			"  Please see the typed subcommand help for detailed usage information.",
		})
	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary host-catalogs update [type] [sub command] [options] [args]",
			"",
			"  This command allows update operations on Boundary host catalog resources. Example:",
			"",
			"    Update a static-type host catalog:",
			"",
			`      $ boundary host-catalogs update static -id hcst_1234567890 -name devops -description "For DevOps usage"`,
			"",
			"  Please see the typed subcommand help for detailed usage information.",
		})
	default:
		helpStr = helpMap["base"]()
	}
	return helpStr + c.Flags().Help()
}

func (c *Command) printListTable(items []*hostcatalogs.HostCatalog) string {
	if len(items) == 0 {
		return "No host catalogs found"
	}

	var output []string
	output = []string{
		"",
		"Host Catalog information:",
	}
	for i, m := range items {
		if i > 0 {
			output = append(output, "")
		}
		if m.Id != "" {
			output = append(output,
				fmt.Sprintf("  ID:                    %s", m.Id),
			)
		} else {
			output = append(output,
				fmt.Sprintf("  ID:                    %s", "(not available)"),
			)
		}
		if c.FlagRecursive && m.ScopeId != "" {
			output = append(output,
				fmt.Sprintf("    Scope ID:            %s", m.ScopeId),
			)
		}
		if m.PluginId != "" {
			output = append(output,
				fmt.Sprintf("    Plugin ID:           %s", m.PluginId),
			)
		}
		if m.Version > 0 {
			output = append(output,
				fmt.Sprintf("    Version:             %d", m.Version),
			)
		}
		if m.Type != "" {
			output = append(output,
				fmt.Sprintf("    Type:                %s", m.Type),
			)
		}
		if m.Name != "" {
			output = append(output,
				fmt.Sprintf("    Name:                %s", m.Name),
			)
		}
		if m.Description != "" {
			output = append(output,
				fmt.Sprintf("    Description:         %s", m.Description),
			)
		}
		if m.WorkerFilter != "" {
			output = append(output,
				fmt.Sprintf("    Worker Filter:       %s", m.WorkerFilter),
			)
		}
		if len(m.AuthorizedActions) > 0 {
			output = append(output,
				"    Authorized Actions:",
				base.WrapSlice(6, m.AuthorizedActions),
			)
		}
	}

	return base.WrapForHelpText(output)
}

func printItemTable(item *hostcatalogs.HostCatalog, resp *api.Response) string {
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
	if item.PluginId != "" {
		nonAttributeMap["Plugin ID"] = item.PluginId
	}
	if item.Type != "" {
		nonAttributeMap["Type"] = item.Type
	}
	if item.SecretsHmac != "" {
		nonAttributeMap["Secrets HMAC"] = item.SecretsHmac
	}
	if item.WorkerFilter != "" {
		nonAttributeMap["Worker Filter"] = item.WorkerFilter
	}

	maxLength := base.MaxAttributesLength(nonAttributeMap, item.Attributes, keySubstMap)

	ret := []string{
		"",
		"Host Catalog information:",
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

	if len(item.Attributes) > 0 {
		ret = append(ret,
			"",
			"  Attributes:",
			base.WrapMap(4, maxLength, item.Attributes),
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
		ret = append(ret, "",
			"  Authorized Actions on Host Catalog's Collections:",
		)
		for _, key := range keys {
			ret = append(ret,
				fmt.Sprintf("    %s:", key),
				base.WrapSlice(6, item.AuthorizedCollectionActions[key]),
			)
		}
	}

	return base.WrapForHelpText(ret)
}

var keySubstMap = map[string]string{
	"address": "Address",
}
