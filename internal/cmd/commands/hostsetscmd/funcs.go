// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package hostsetscmd

import (
	"fmt"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/hostsets"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/common"
)

func init() {
	extraActionsFlagsMapFunc = extraActionsFlagsMapFuncImpl
	extraSynopsisFunc = extraSynopsisFuncImpl
	extraFlagsFunc = extraFlagsFuncImpl
	extraFlagsHandlingFunc = extraFlagsHandlingFuncImpl
	executeExtraActions = executeExtraActionsImpl
}

type extraCmdVars struct {
	flagHosts []string
}

func extraActionsFlagsMapFuncImpl() map[string][]string {
	return map[string][]string{
		"add-hosts":    {"id", "host", "version"},
		"set-hosts":    {"id", "host", "version"},
		"remove-hosts": {"id", "host", "version"},
	}
}

func extraSynopsisFuncImpl(c *Command) string {
	switch c.Func {
	case "add-hosts":
		return "Add hosts to the specified host set"
	case "remove-hosts":
		return "Remove hosts from the specified host set"
	case "set-hosts":
		return "Set the full contents of the hosts on the specified host set"
	default:
		return common.SynopsisFunc(c.Func, "host set")
	}
}

func (c *Command) extraHelpFunc(helpMap map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "":
		return base.WrapForHelpText([]string{
			"Usage: boundary host-sets [sub command] [options] [args]",
			"",
			"  This command allows operations on Boundary host set resources. Example:",
			"",
			"    Read a host set:",
			"",
			`      $ boundary host-sets read -id hsst_1234567890`,
			"",
			"  Please see the host-sets subcommand help for detailed usage information.",
		})
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary host-sets create [type] [sub command] [options] [args]",
			"",
			"  This command allows create operations on Boundary host set resources. Example:",
			"",
			"    Create a static-type host set:",
			"",
			`      $ boundary host-sets create static -name prodops -description "For ProdOps usage"`,
			"",
			"  Please see the typed subcommand help for detailed usage information.",
		})
	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary host-sets update [type] [sub command] [options] [args]",
			"",
			"  This command allows update operations on Boundary host set resources. Example:",
			"",
			"    Update a static-type host set:",
			"",
			`      $ boundary host-sets update static -id hsst_1234567890 -name devops -description "For DevOps usage"`,
			"",
			"  Please see the typed subcommand help for detailed usage information.",
		})
	case "add-hosts":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary host-sets add-hosts [sub command] [options] [args]",
			"",
			"  This command allows adding hosts to host set resources, if the types match and the operation is allowed by the given host set type. Example:",
			"",
			"    Add static-type hosts to a static-type host set:",
			"",
			`      $ boundary host-sets add-hosts -id hsst_1234567890 -host hst_1234567890 -host hst_0987654321`,
			"",
			"",
		})
	case "remove-hosts":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary host-sets remove-hosts [sub command] [options] [args]",
			"",
			"  This command allows removing hosts from host set resources, if the types match and the operation is allowed by the given host set type. Example:",
			"",
			"    Remove static-type hosts from a static-type host set:",
			"",
			`      $ boundary host-sets remove-hosts -id hsst_1234567890 -host hst_0987654321`,
			"",
			"",
		})
	case "set-hosts":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary host-sets set-hosts [sub command] [options] [args]",
			"",
			"  This command allows setting the complete set of hosts on host set resources, if the types match and the operation is allowed by the given host set type. Example:",
			"",
			"    Set the complete set of static-type hosts on a static-type host set:",
			"",
			`      $ boundary host-sets remove-hosts -id hsst_1234567890 -host hst_1234567890`,
			"",
			"",
		})
	default:
		helpStr = helpMap[c.Func]()
	}
	return helpStr + c.Flags().Help()
}

func extraFlagsFuncImpl(c *Command, _ *base.FlagSets, f *base.FlagSet) {
	for _, name := range flagsMap[c.Func] {
		switch name {
		case "host":
			f.StringSliceVar(&base.StringSliceVar{
				Name:   "host",
				Target: &c.flagHosts,
				Usage:  "The hosts to add, remove, or set. May be specified multiple times.",
			})
		}
	}
}

func extraFlagsHandlingFuncImpl(c *Command, _ *base.FlagSets, opts *[]hostsets.Option) bool {
	switch c.Func {
	case "add-hosts", "remove-hosts":
		if len(c.flagHosts) == 0 {
			c.UI.Error("No hosts supplied via -host")
			return false
		}

	case "set-hosts":
		switch len(c.flagHosts) {
		case 0:
			c.UI.Error("No hosts supplied via -host")
			return false
		case 1:
			if c.flagHosts[0] == "null" {
				c.flagHosts = nil
			}
		}
	}

	return true
}

func executeExtraActionsImpl(c *Command, origResp *api.Response, origItem *hostsets.HostSet, origItems []*hostsets.HostSet, origError error, hostsetClient *hostsets.Client, version uint32, opts []hostsets.Option) (*api.Response, *hostsets.HostSet, []*hostsets.HostSet, error) {
	switch c.Func {
	case "add-hosts":
		result, err := hostsetClient.AddHosts(c.Context, c.FlagId, version, c.flagHosts, opts...)
		if err != nil {
			return nil, nil, nil, err
		}
		return result.GetResponse(), result.GetItem(), nil, err
	case "remove-hosts":
		result, err := hostsetClient.RemoveHosts(c.Context, c.FlagId, version, c.flagHosts, opts...)
		if err != nil {
			return nil, nil, nil, err
		}
		return result.GetResponse(), result.GetItem(), nil, err
	case "set-hosts":
		result, err := hostsetClient.SetHosts(c.Context, c.FlagId, version, c.flagHosts, opts...)
		if err != nil {
			return nil, nil, nil, err
		}
		return result.GetResponse(), result.GetItem(), nil, err
	}
	return origResp, origItem, origItems, origError
}

func (c *Command) printListTable(items []*hostsets.HostSet) string {
	if len(items) == 0 {
		return "No host sets found"
	}

	var output []string
	output = []string{
		"",
		"Host Set information:",
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
		if item.SyncIntervalSeconds != 0 {
			output = append(output,
				fmt.Sprintf("    Sync Interval:       %d seconds", item.SyncIntervalSeconds),
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

func printItemTable(item *hostsets.HostSet, resp *api.Response) string {
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
	if item.PreferredEndpoints != nil {
		nonAttributeMap["Preferred Endpoints"] = item.PreferredEndpoints
	}
	if item.SyncIntervalSeconds != 0 {
		nonAttributeMap["Sync Interval"] = fmt.Sprintf("%d seconds", item.SyncIntervalSeconds)
	}

	maxLength := base.MaxAttributesLength(nonAttributeMap, item.Attributes, keySubstMap)

	ret := []string{
		"",
		"Host Set information:",
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

	if len(item.HostIds) > 0 {
		ret = append(ret,
			"",
			"  Host IDs:",
			base.WrapSlice(4, item.HostIds),
		)
	}

	return base.WrapForHelpText(ret)
}

var keySubstMap = map[string]string{}
