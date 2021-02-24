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

func extraFlagsHandlingFuncImpl(c *Command, opts *[]hostsets.Option) int {
	switch c.Func {
	case "add-hosts", "remove-hosts":
		if len(c.flagHosts) == 0 {
			c.UI.Error("No hosts supplied via -host")
			return 1
		}

	case "set-hosts":
		switch len(c.flagHosts) {
		case 0:
			c.UI.Error("No hosts supplied via -host")
			return 1
		case 1:
			if c.flagHosts[0] == "null" {
				c.flagHosts = nil
			}
		}
	}

	return 0
}

func executeExtraActionsImpl(c *Command, origResult api.GenericResult, origError error, hostsetClient *hostsets.Client, version uint32, opts []hostsets.Option) (api.GenericResult, error) {
	switch c.Func {
	case "add-hosts":
		return hostsetClient.AddHosts(c.Context, c.FlagId, version, c.flagHosts, opts...)
	case "remove-hosts":
		return hostsetClient.RemoveHosts(c.Context, c.FlagId, version, c.flagHosts, opts...)
	case "set-hosts":
		return hostsetClient.SetHosts(c.Context, c.FlagId, version, c.flagHosts, opts...)
	}
	return origResult, origError
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
	for i, m := range items {
		if i > 0 {
			output = append(output, "")
		}
		if true {
			output = append(output,
				fmt.Sprintf("  ID:                    %s", m.Id),
				fmt.Sprintf("    Version:             %d", m.Version),
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
		if len(m.AuthorizedActions) > 0 {
			output = append(output,
				"    Authorized Actions:",
				base.WrapSlice(6, m.AuthorizedActions),
			)
		}
	}

	return base.WrapForHelpText(output)
}

func printItemTable(in *hostsets.HostSet) string {
	nonAttributeMap := map[string]interface{}{
		"ID":              in.Id,
		"Version":         in.Version,
		"Type":            in.Type,
		"Created Time":    in.CreatedTime.Local().Format(time.RFC1123),
		"Updated Time":    in.UpdatedTime.Local().Format(time.RFC1123),
		"Host Catalog ID": in.HostCatalogId,
	}

	if in.Name != "" {
		nonAttributeMap["Name"] = in.Name
	}
	if in.Description != "" {
		nonAttributeMap["Description"] = in.Description
	}

	maxLength := base.MaxAttributesLength(nonAttributeMap, in.Attributes, keySubstMap)

	ret := []string{
		"",
		"Host Set information:",
		base.WrapMap(2, maxLength+2, nonAttributeMap),
		"",
		"  Scope:",
		base.ScopeInfoForOutput(in.Scope, maxLength),
	}

	if len(in.AuthorizedActions) > 0 {
		ret = append(ret,
			"",
			"  Authorized Actions:",
			base.WrapSlice(4, in.AuthorizedActions),
		)
	}

	if len(in.HostIds) > 0 {
		ret = append(ret,
			"",
			"  Host IDs:",
			base.WrapSlice(4, in.HostIds),
		)
	}

	if len(in.Attributes) > 0 {
		ret = append(ret,
			"",
			"  Attributes:",
			base.WrapMap(4, maxLength, in.Attributes),
		)
	}

	return base.WrapForHelpText(ret)
}

var keySubstMap = map[string]string{}
