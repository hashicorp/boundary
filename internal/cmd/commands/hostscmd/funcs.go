package hostscmd

import (
	"fmt"
	"time"

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
		return "No host sets found"
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
		if true {
			output = append(output,
				fmt.Sprintf("  ID:                    %s", item.Id),
			)
		}
		if item.Version > 0 {
			output = append(output,
				fmt.Sprintf("    Version:             %d", item.Version),
			)
		}
		if true {
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

func printItemTable(in *hosts.Host) string {
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
		"Host information:",
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

	if len(in.HostSetIds) > 0 {
		ret = append(ret,
			"",
			"  Host Set IDs:",
			base.WrapSlice(4, in.HostSetIds),
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
