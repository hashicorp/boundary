// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package workerscmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/workers"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func init() {
	extraActionsFlagsMapFunc = extraActionsFlagsMapFuncImpl
	extraSynopsisFunc = extraSynopsisFuncImpl
	extraFlagsFunc = extraFlagsFuncImpl
	extraFlagsHandlingFunc = extraFlagsHandlingFuncImpl
	executeExtraActions = executeExtraActionsImpl
}

func extraActionsFlagsMapFuncImpl() map[string][]string {
	return map[string][]string{
		"add-worker-tags":    {"id", "tag", "version"},
		"set-worker-tags":    {"id", "tag", "version"},
		"remove-worker-tags": {"id", "tag", "version"},
	}
}

func extraSynopsisFuncImpl(c *Command) string {
	switch c.Func {
	case "add-worker-tags":
		return "Add api tags to the specified worker"
	case "set-worker-tags":
		return "Set api tags for the specified worker"
	case "remove-worker-tags":
		return "Remove api tags from the specified worker"
	default:
		return ""
	}
}

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
	case "add-worker-tags":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary workers add-worker-tags [options] [args]",
			"",
			"  This command allows adding api tags to worker resources. Example:",
			"",
			"    Add a set of api tags to a specified worker:",
			"",
			`      & boundary workers add-worker-tags -id w_1234567890 -tag "key1=val-a" -tag "key2=val-b,val-c"`,
			"",
			"",
		})
	case "set-worker-tags":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary workers set-worker-tags [options] [args]",
			"",
			"  This command allows setting api tags for worker resources. Example:",
			"",
			"    Set api tags for a specified worker:",
			"",
			`      & boundary workers set-worker-tags -id w_1234567890 -tag "key1=val-a" -tag "key2=val-b,val-c"`,
			"",
			"",
		})
	case "remove-worker-tags":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary workers remove-worker-tags [options] [args]",
			"",
			"  This command allows removing api tags from worker resources. Example:",
			"",
			"    Remove a set of api tags to a specified worker:",
			"",
			`      & boundary workers remove-worker-tags -id w_1234567890 -tag "key1=val-a" -tag "key2=val-b,val-c"`,
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
		case "tag":
			var nullCheckFn func() bool = nil
			switch {
			case strings.ToLower(c.Func[:3]) == "set":
				nullCheckFn = func() bool { return true }
			default:
			}
			f.StringSliceMapVar(&base.StringSliceMapVar{
				Name:      "tag",
				Target:    &c.FlagTags,
				NullCheck: nullCheckFn,
				Usage:     "The api tag resources to add, remove, or set.",
			})
		}
	}
}

func extraFlagsHandlingFuncImpl(c *Command, _ *base.FlagSets, opts *[]workers.Option) bool {
	switch c.Func {
	case "add-worker-tags", "remove-worker-tags":
		if len(c.FlagTags) == 0 {
			c.UI.Error("No tags supplied via -tag")
			return false
		}
	case "set-worker-tags":
		switch len(c.FlagTags) {
		case 0:
			c.UI.Error("No tags supplied via -tag")
			return false
		case 1:
			if v, found := c.FlagTags["null"]; found && v == nil {
				c.FlagTags = nil
			}
		}
	}
	return true
}

func executeExtraActionsImpl(c *Command, inResp *api.Response, inItem *workers.Worker, inItems []*workers.Worker, inErr error, workerClient *workers.Client, version uint32, opts []workers.Option) (*api.Response, *workers.Worker, []*workers.Worker, error) {
	switch c.Func {
	case "add-worker-tags":
		result, err := workerClient.AddWorkerTags(c.Context, c.FlagId, version, c.FlagTags, opts...)
		if err != nil {
			return nil, nil, nil, err
		}
		return result.GetResponse(), result.GetItem(), nil, err
	case "set-worker-tags":
		result, err := workerClient.SetWorkerTags(c.Context, c.FlagId, version, c.FlagTags, opts...)
		if err != nil {
			return nil, nil, nil, err
		}
		return result.GetResponse(), result.GetItem(), nil, err
	case "remove-worker-tags":
		result, err := workerClient.RemoveWorkerTags(c.Context, c.FlagId, version, c.FlagTags, opts...)
		if err != nil {
			return nil, nil, nil, err
		}
		return result.GetResponse(), result.GetItem(), nil, err
	}
	return inResp, inItem, inItems, inErr
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
		if item.Address != "" {
			output = append(output,
				fmt.Sprintf("    Address:                 %s", item.Address),
			)
		}
		if item.ReleaseVersion != "" {
			output = append(output,
				fmt.Sprintf("    ReleaseVersion:          %s", item.ReleaseVersion),
			)
		}
		if !item.LastStatusTime.IsZero() {
			output = append(output,
				fmt.Sprintf("    Last Status Time:        %s", item.LastStatusTime.Format(time.RFC1123)),
			)
		}
		if len(item.DirectlyConnectedDownstreamWorkers) > 0 {
			output = append(output,
				"    Directly Connected Downstream Workers:",
				base.WrapSlice(6, item.DirectlyConnectedDownstreamWorkers))
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
	if item.Type != "" {
		nonAttributeMap["Type"] = item.Type
	}
	if item.Address != "" {
		nonAttributeMap["Address"] = item.Address
	}
	if item.ReleaseVersion != "" {
		nonAttributeMap["Release Version"] = item.ReleaseVersion
	}
	if !item.LastStatusTime.IsZero() {
		nonAttributeMap["Last Status Time"] = item.LastStatusTime
	}
	if item.ControllerGeneratedActivationToken != "" {
		nonAttributeMap["Controller-Generated Activation Token"] = item.ControllerGeneratedActivationToken
	}
	if item.LocalStorageState != "" {
		nonAttributeMap["Local Storage State"] = item.LocalStorageState
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

	if len(item.CanonicalTags) > 0 || len(item.ApiTags) > 0 || len(item.ConfigTags) > 0 {
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
				"    Configuration:",
				base.WrapMap(6, 2, tagMap),
			)
		}
		if len(item.ApiTags) > 0 {
			tagMap := make(map[string]any, len(item.ApiTags))
			for k, v := range item.ApiTags {
				tagMap[k] = v
			}
			ret = append(ret,
				"    Api:",
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

	if len(item.RemoteStorageState) > 0 {
		ret = append(ret,
			"",
			"  Remote Storage State:",
		)
		for storageBucketId, state := range item.RemoteStorageState {
			ret = append(ret,
				fmt.Sprintf("    %s:", storageBucketId),
				fmt.Sprintf("        Status: %s", state.Status),
				"        Permissions:",
				fmt.Sprintf("            Write: %s", state.Permissions.Write),
				fmt.Sprintf("            Read: %s", state.Permissions.Read),
				fmt.Sprintf("            Delete: %s", state.Permissions.Delete),
			)
		}
	}

	if len(item.DirectlyConnectedDownstreamWorkers) > 0 {
		ret = append(ret,
			"",
			"  Directly Connected Downstream Workers:",
			base.WrapSlice(4, item.DirectlyConnectedDownstreamWorkers),
		)
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
