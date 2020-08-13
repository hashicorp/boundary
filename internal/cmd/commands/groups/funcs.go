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
	common.PopulateCommonFlags(c.Command, f, resource.Group, flagNames)

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

func generateGroupTableOutput(group *groups.Group) string {
	var output []string
	if true {
		output = []string{
			"",
			"Group information:",
			fmt.Sprintf("  ID:               %s", group.Id),
			fmt.Sprintf("  Created At:       %s", group.CreatedTime.Local().Format(time.RFC3339)),
			fmt.Sprintf("  Updated At:       %s", group.UpdatedTime.Local().Format(time.RFC3339)),
			fmt.Sprintf("  Version:          %d", group.Version),
		}
	}
	if group.Name != "" {
		output = append(output,
			fmt.Sprintf("  Name:             %s", group.Name),
		)
	}
	if group.Description != "" {
		output = append(output,
			fmt.Sprintf("  Description:      %s", group.Description),
		)
	}
	if len(group.Members) > 0 {
		output = append(output,
			fmt.Sprintf("  Members:       %s", ""),
		)
	}
	for _, member := range group.Members {
		output = append(output,
			fmt.Sprintf("    ID:             %s", member.Id),
			fmt.Sprintf("      Scope ID:     %s", member.ScopeId),
		)
	}
	return base.WrapForHelpText(output)
}
