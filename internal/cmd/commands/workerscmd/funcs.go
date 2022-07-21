package workerscmd

import (
	"fmt"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/workers"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func (c *Command) extraHelpFunc(helpMap map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "":
		return base.WrapForHelpText([]string{
			"Usage: boundary workers [sub command] [options] [args]",
			"",
			"  This command allows operations on Boundary worker resources. Example:",
			"",
			"    Read a worker:",
			"",
			`      $ boundary workers read -id w_1234567890`,
			"",
			"  Please see the workers subcommand help for detailed usage information.",
		})
	default:
		helpStr = helpMap[c.Func]()
	}
	return helpStr + c.Flags().Help()
}

func (c *Command) printListTable(items []*workers.Worker) string {
	if len(items) == 0 {
		return "No workers found"
	}

	var output []string
	output = []string{
		"",
		"Worker information:",
	}
	for i, item := range items {
		if i > 0 {
			output = append(output, "")
		}
		if item.Id != "" {
			output = append(output,
				fmt.Sprintf("  ID:                        %s", item.Id),
			)
		} else {
			output = append(output,
				fmt.Sprintf("  ID:                        %s", "(not available)"),
			)
		}
		if c.FlagRecursive && item.ScopeId != "" {
			output = append(output,
				fmt.Sprintf("    Scope ID:                %s", item.ScopeId),
			)
		}
		if item.Type != "" {
			output = append(output,
				fmt.Sprintf("    Type:                    %s", item.Type),
			)
		}
		if item.Version > 0 {
			output = append(output,
				fmt.Sprintf("    Version:                 %d", item.Version),
			)
		}
		if item.Name != "" {
			output = append(output,
				fmt.Sprintf("    Name:                    %s", item.Name),
			)
		}
		if item.Description != "" {
			output = append(output,
				fmt.Sprintf("    Description:             %s", item.Description),
			)
		}
		if item.Address != "" {
			output = append(output,
				fmt.Sprintf("    Address:                 %s", item.Address),
			)
		}
		if !item.LastStatusTime.IsZero() {
			output = append(output,
				fmt.Sprintf("    Last Status Time:        %s", item.LastStatusTime.Format(time.RFC1123)),
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

func printItemTable(item *workers.Worker, resp *api.Response) string {
	nonAttributeMap := map[string]interface{}{}
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
	if item.Type != "" {
		nonAttributeMap["Type"] = item.Type
	}
	if item.Address != "" {
		nonAttributeMap["Address"] = item.Address
	}
	if !item.LastStatusTime.IsZero() {
		nonAttributeMap["Last Status Time"] = item.LastStatusTime
	}

	resultMap := resp.Map
	if count, ok := resultMap[globals.ActiveConnectionCountField]; ok {
		nonAttributeMap["Active Connection Count"] = count
	}

	maxLength := base.MaxAttributesLength(nonAttributeMap, nil, nil)

	ret := []string{
		"",
		"Worker information:",
		base.WrapMap(2, maxLength+2, nonAttributeMap),
	}

	if item.Scope != nil {
		ret = append(ret,
			"",
			"  Scope:",
			base.ScopeInfoForOutput(item.Scope, maxLength),
		)
	}

	if len(item.CanonicalTags) > 0 || len(item.ConfigTags) > 0 {
		ret = append(ret,
			"",
			"  Tags:",
		)
		if len(item.ConfigTags) > 0 {
			tagMap := make(map[string]any, len(item.ConfigTags))
			for k, v := range item.ConfigTags {
				tagMap[k] = v
			}
			ret = append(ret,
				"    Worker Configuration:",
				base.WrapMap(6, 2, tagMap),
			)
		}
		if len(item.CanonicalTags) > 0 {
			tagMap := make(map[string]any, len(item.CanonicalTags))
			for k, v := range item.CanonicalTags {
				tagMap[k] = v
			}
			ret = append(ret,
				"    Canonical:",
				base.WrapMap(6, 2, tagMap),
			)
		}
	}

	if len(item.AuthorizedActions) > 0 {
		ret = append(ret,
			"",
			"  Authorized Actions:",
			base.WrapSlice(4, item.AuthorizedActions),
		)
	}

	return base.WrapForHelpText(ret)
}
