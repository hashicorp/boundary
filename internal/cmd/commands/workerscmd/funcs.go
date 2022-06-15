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
		if item.CanonicalAddress != "" {
			output = append(output,
				fmt.Sprintf("    Canonical Address:       %s", item.CanonicalAddress),
			)
		}
		if !item.LastStatusTime.IsZero() {
			output = append(output,
				fmt.Sprintf("    Last Status Time:        %s", item.LastStatusTime.Format(time.RFC1123)),
			)
		}
		if true {
			output = append(output,
				fmt.Sprintf("    Active Connection Count: %d", item.ActiveConnectionCount),
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

func printItemTable(result api.GenericResult) string {
	item := result.GetItem().(*workers.Worker)
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
	if !item.LastStatusTime.IsZero() {
		nonAttributeMap["Last Status Time"] = item.LastStatusTime
	}

	resultMap := result.GetResponse().Map
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

	var workerProvidedTags map[string][]string
	var workerProvidedAddress string
	if item.WorkerProvidedConfiguration != nil {
		config := item.WorkerProvidedConfiguration
		configMap := make(map[string]any)
		if config.Address != "" {
			configMap["Address"] = config.Address
			workerProvidedAddress = config.Address
		}
		if config.Name != "" {
			configMap["Name"] = config.Name
		}
		ret = append(ret,
			"",
			"  Worker-Provided Configuration:",
			base.WrapMap(4, maxLength, configMap),
		)
		workerProvidedTags = config.Tags
	}

	if len(item.Address) > 0 || len(item.CanonicalAddress) > 0 || len(workerProvidedAddress) > 0 {
		ret = append(ret,
			"",
			"  Address:",
		)
		if len(item.Address) > 0 {
			ret = append(ret,
				"    Item (via API):",
				"      "+item.Address,
			)
		}
		if len(workerProvidedAddress) > 0 {
			ret = append(ret,
				"    Worker Configuration:",
				"      "+workerProvidedAddress,
			)
		}
		if len(item.CanonicalAddress) > 0 {
			ret = append(ret,
				"    Canonical:",
				"      "+item.CanonicalAddress,
			)
		}
	}

	if len(item.Tags) > 0 || len(item.CanonicalTags) > 0 || len(workerProvidedTags) > 0 {
		ret = append(ret,
			"",
			"  Tags:",
		)
		if len(item.Tags) > 0 {
			tagMap := make(map[string]any, len(item.Tags))
			for k, v := range item.Tags {
				tagMap[k] = v
			}
			ret = append(ret,
				"    Item (via API):",
				base.WrapMap(6, 2, tagMap),
			)
		}
		if len(workerProvidedTags) > 0 {
			tagMap := make(map[string]any, len(workerProvidedTags))
			for k, v := range workerProvidedTags {
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
