package groups

import (
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/boundary/api/groups"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/common"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/mitchellh/go-wordwrap"
)

func memberSynopsisFunc(inFunc string) string {
	var in string
	switch {
	case strings.HasPrefix(inFunc, "add"):
		in = "Add users to"
	case strings.HasPrefix(inFunc, "set"):
		in = "Set the full contents of the users on"
	case strings.HasPrefix(inFunc, "remove"):
		in = "Remove users from"
	}
	return wordwrap.WrapString(fmt.Sprintf("%s a group within Boundary", in), base.TermWidth)
}

func addMembersHelp() string {
	return base.WrapForHelpText([]string{
		"Usage: boundary groups add-members [options] [args]",
		"",
		`  Adds members (users) to a group given its ID. The "user" flag can be specified multiple times. Example:`,
		"",
		`    $ boundary groups add-members -id g_1234567890 -user u_1234567890`,
	})
}

func setMembersHelp() string {
	return base.WrapForHelpText([]string{
		"Usage: boundary groups set-members [options] [args]",
		"",
		`  Sets the complete set of members (users) on a group given its ID. The "user" flag can be specified multiple times. Example:`,
		"",
		`    $ boundary groups set-principals -id g_1234567890 -user u_anon -user u_1234567890`,
	})
}

func removeMembersHelp() string {
	return base.WrapForHelpText([]string{
		"Usage: boundary groups remove-members [options] [args]",
		"",
		`  Removes members (users) from a group given its ID. The "user" flag can be specified multiple times. Example:`,
		"",
		`    $ boundary groups remove-members -id r_1234567890 -user u_1234567890`,
	})
}

func populateFlags(c *Command, f *base.FlagSet, flagNames []string) {
	common.PopulateCommonFlags(c.Command, f, resource.Group.String(), flagNames)

	for _, name := range flagNames {
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

func generateGroupTableOutput(in *groups.Group) string {
	var ret []string

	nonAttributeMap := map[string]interface{}{
		"ID":           in.Id,
		"Version":      in.Version,
		"Created Time": in.CreatedTime.Local().Format(time.RFC3339),
		"Updated Time": in.UpdatedTime.Local().Format(time.RFC3339),
	}

	if in.Name != "" {
		nonAttributeMap["Name"] = in.Name
	}
	if in.Description != "" {
		nonAttributeMap["Description"] = in.Description
	}

	ret = append(ret, "", "Group information:")

	ret = append(ret,
		base.WrapMap(2, 0, nonAttributeMap),
	)

	if len(in.Members) > 0 {
		ret = append(ret,
			fmt.Sprintf("  Members:      %s", ""),
		)
	}
	for _, member := range in.Members {
		ret = append(ret,
			fmt.Sprintf("    ID:         %s", member.Id),
			fmt.Sprintf("      Scope ID: %s", member.ScopeId),
		)
	}
	return base.WrapForHelpText(ret)
}
