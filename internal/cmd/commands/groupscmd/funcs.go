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
	extraFlagsFunc = extraFlagsFuncImpl
	extraFlagsHandlingFunc = extraFlagsHandlingFuncImpl
	executeExtraActions = executeExtraActionsImpl
}

type extraCmdVars struct {
	flagMembers []string
}

var extraActionsFlagsMap = map[string][]string{
	"add-members":    {"id", "member", "version"},
	"remove-members": {"id", "member", "version"},
	"set-members":    {"id", "member", "version"},
}

func (c *Command) extraSynopsisFunc() string {
	switch c.Func {
	case "add-members", "set-members", "remove-members":
		var in string
		switch {
		case strings.HasPrefix(c.Func, "add"):
			in = "Add members to"
		case strings.HasPrefix(c.Func, "set"):
			in = "Set the full contents of the users on"
		case strings.HasPrefix(c.Func, "remove"):
			in = "Remove users from"
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
			`  Adds members (users) to a group given its ID. The "user" flag can be specified multiple times. Example:`,
			"",
			`    $ boundary groups add-members -id g_1234567890 -user u_1234567890`,
			"",
			"",
		})

	case "set-members":
		return base.WrapForHelpText([]string{
			"Usage: boundary groups set-members [options] [args]",
			"",
			`  Sets the complete set of members (users) on a group given its ID. The "user" flag can be specified multiple times. Example:`,
			"",
			`    $ boundary groups set-principals -id g_1234567890 -user u_anon -user u_1234567890`,
			"",
			"",
		})

	case "remove-members":
		return base.WrapForHelpText([]string{
			"Usage: boundary groups remove-members [options] [args]",
			"",
			`  Removes members (users) from a group given its ID. The "user" flag can be specified multiple times. Example:`,
			"",
			`    $ boundary groups remove-members -id g_1234567890 -user u_1234567890`,
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

func extraFlagsHandlingFuncImpl(c *Command, opts *[]groups.Option) int {
	switch c.Func {
	case "add-members", "remove-members":
		if len(c.flagMembers) == 0 {
			c.UI.Error("No members supplied via -member")
			return 1
		}

	case "set-members":
		switch len(c.flagMembers) {
		case 0:
			c.UI.Error("No members supplied via -member")
			return 1
		case 1:
			if c.flagMembers[0] == "null" {
				c.flagMembers = nil
			}
		}
	}

	return 0
}

func executeExtraActionsImpl(c *Command, origResult api.GenericResult, origError error, groupClient *groups.Client, version uint32, opts []groups.Option) (api.GenericResult, error) {
	switch c.Func {
	case "add-members":
		return groupClient.AddMembers(c.Context, c.FlagId, version, c.flagMembers, opts...)
	case "set-members":
		return groupClient.SetMembers(c.Context, c.FlagId, version, c.flagMembers, opts...)
	case "remove-members":
		return groupClient.RemoveMembers(c.Context, c.FlagId, version, c.flagMembers, opts...)
	}
	return origResult, origError
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
	for i, g := range items {
		if i > 0 {
			output = append(output, "")
		}
		if true {
			output = append(output,
				fmt.Sprintf("  ID:                    %s", g.Id),
			)
		}
		if c.FlagRecursive {
			output = append(output,
				fmt.Sprintf("    Scope ID:            %s", g.Scope.Id),
			)
		}
		if true {
			output = append(output,
				fmt.Sprintf("    Version:             %d", g.Version),
			)
		}
		if g.Name != "" {
			output = append(output,
				fmt.Sprintf("    Name:                %s", g.Name),
			)
		}
		if g.Description != "" {
			output = append(output,
				fmt.Sprintf("    Description:         %s", g.Description),
			)
		}
		if len(g.AuthorizedActions) > 0 {
			output = append(output,
				"    Authorized Actions:",
				base.WrapSlice(6, g.AuthorizedActions),
			)
		}
	}

	return base.WrapForHelpText(output)
}

func printItemTable(item *groups.Group) string {
	nonAttributeMap := map[string]interface{}{
		"ID":           item.Id,
		"Version":      item.Version,
		"Created Time": item.CreatedTime.Local().Format(time.RFC1123),
		"Updated Time": item.UpdatedTime.Local().Format(time.RFC1123),
	}

	if item.Name != "" {
		nonAttributeMap["Name"] = item.Name
	}
	if item.Description != "" {
		nonAttributeMap["Description"] = item.Description
	}

	maxLength := base.MaxAttributesLength(nonAttributeMap, nil, nil)

	var groupMaps []map[string]interface{}
	if len(item.Members) > 0 {
		for _, member := range item.Members {
			m := map[string]interface{}{
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
		"",
		"  Scope:",
		base.ScopeInfoForOutput(item.Scope, maxLength),
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
