// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package groupscmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/groups"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/mitchellh/go-wordwrap"
)

func init() {
	extraActionsFlagsMapFunc = extraActionsFlagsMapFuncImpl
	extraSynopsisFunc = extraSynopsisFuncImpl
	extraFlagsFunc = extraFlagsFuncImpl
	extraFlagsHandlingFunc = extraFlagsHandlingFuncImpl
	executeExtraActions = executeExtraActionsImpl
}

type extraCmdVars struct {
	flagMembers []string
}

func extraActionsFlagsMapFuncImpl() map[string][]string {
	return map[string][]string{
		"add-members":    {"id", "member", "version"},
		"remove-members": {"id", "member", "version"},
		"set-members":    {"id", "member", "version"},
	}
}

func extraSynopsisFuncImpl(c *Command) string {
	switch c.Func {
	case "add-members", "set-members", "remove-members":
		var in string
		switch {
		case strings.HasPrefix(c.Func, "add"):
			in = "Add members to"
		case strings.HasPrefix(c.Func, "set"):
			in = "Set the full contents of the members on"
		case strings.HasPrefix(c.Func, "remove"):
			in = "Remove members from"
		}
		return wordwrap.WrapString(fmt.Sprintf("%s a group", in), base.TermWidth)

	default:
		return ""
	}
}

func (c *Command) extraHelpFunc(helpMap map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "":
		return helpMap["base"]()

	case "add-members":
		return base.WrapForHelpText([]string{
			"Usage: boundary groups add-members [options] [args]",
			"",
			`  Adds members (users) to a group given its ID. The "member" flag can be specified multiple times. Example:`,
			"",
			`    $ boundary groups add-members -id g_1234567890 -member u_1234567890`,
			"",
			"",
		})

	case "set-members":
		return base.WrapForHelpText([]string{
			"Usage: boundary groups set-members [options] [args]",
			"",
			`  Sets the complete set of members (users) on a group given its ID. The "member" flag can be specified multiple times. Example:`,
			"",
			`    $ boundary groups set-principals -id g_1234567890 -member u_anon -member u_1234567890`,
			"",
			"",
		})

	case "remove-members":
		return base.WrapForHelpText([]string{
			"Usage: boundary groups remove-members [options] [args]",
			"",
			`  Removes members (users) from a group given its ID. The "member" flag can be specified multiple times. Example:`,
			"",
			`    $ boundary groups remove-members -id g_1234567890 -member u_1234567890`,
			"",
			"",
		})
	}
	return helpStr + c.Flags().Help()
}

func extraFlagsFuncImpl(c *Command, _ *base.FlagSets, f *base.FlagSet) {
	for _, name := range flagsMap[c.Func] {
		switch name {
		case "member":
			f.StringSliceVar(&base.StringSliceVar{
				Name:   "member",
				Target: &c.flagMembers,
				Usage:  "The members (users) to add, remove, or set. May be specified multiple times.",
			})
		}
	}
}

func extraFlagsHandlingFuncImpl(c *Command, _ *base.FlagSets, opts *[]groups.Option) bool {
	switch c.Func {
	case "add-members", "remove-members":
		if len(c.flagMembers) == 0 {
			c.UI.Error("No members supplied via -member")
			return false
		}

	case "set-members":
		switch len(c.flagMembers) {
		case 0:
			c.UI.Error("No members supplied via -member")
			return false
		case 1:
			if c.flagMembers[0] == "null" {
				c.flagMembers = nil
			}
		}
	}

	return true
}

func executeExtraActionsImpl(c *Command, origResp *api.Response, origItem *groups.Group, origItems []*groups.Group, origError error, groupClient *groups.Client, version uint32, opts []groups.Option) (*api.Response, *groups.Group, []*groups.Group, error) {
	switch c.Func {
	case "add-members":
		result, err := groupClient.AddMembers(c.Context, c.FlagId, version, c.flagMembers, opts...)
		if err != nil {
			return nil, nil, nil, err
		}
		return result.GetResponse(), result.GetItem(), nil, err
	case "set-members":
		result, err := groupClient.SetMembers(c.Context, c.FlagId, version, c.flagMembers, opts...)
		if err != nil {
			return nil, nil, nil, err
		}
		return result.GetResponse(), result.GetItem(), nil, err
	case "remove-members":
		result, err := groupClient.RemoveMembers(c.Context, c.FlagId, version, c.flagMembers, opts...)
		if err != nil {
			return nil, nil, nil, err
		}
		return result.GetResponse(), result.GetItem(), nil, err
	}
	return origResp, origItem, origItems, origError
}

func (c *Command) printListTable(items []*groups.Group) string {
	if len(items) == 0 {
		return "No groups found"
	}
	var output []string
	output = []string{
		"",
		"Group information:",
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

func printItemTable(item *groups.Group, resp *api.Response) string {
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

	maxLength := base.MaxAttributesLength(nonAttributeMap, nil, nil)

	var groupMaps []map[string]any
	if len(item.Members) > 0 {
		for _, member := range item.Members {
			m := map[string]any{
				"ID":       member.Id,
				"Scope ID": member.ScopeId,
			}
			groupMaps = append(groupMaps, m)
		}
		if l := len("Scope ID"); l > maxLength {
			maxLength = l
		}
	}

	ret := []string{
		"",
		"Group information:",
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

	if len(item.Members) > 0 {
		ret = append(ret,
			"",
			"  Members:",
		)
		for _, m := range groupMaps {
			ret = append(ret,
				base.WrapMap(4, maxLength, m),
				"",
			)
		}
	}

	return base.WrapForHelpText(ret)
}
