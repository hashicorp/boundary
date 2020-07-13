package roles

import (
	"fmt"
	"net/textproto"
	"strings"
	"time"

	"github.com/hashicorp/watchtower/api/roles"
	"github.com/hashicorp/watchtower/internal/cmd/base"
	"github.com/mitchellh/go-wordwrap"
)

func synopsisFunc(inFunc string) string {
	if inFunc == "" {
		return wordwrap.WrapString("Manage Watchtower roles", 80)
	}
	return wordwrap.WrapString(fmt.Sprintf("%s a role within Watchtower", textproto.CanonicalMIMEHeaderKey(inFunc)), 80)
}

func principalsSynopsisFunc(inPrinc string) string {
	var in string
	switch inPrinc {
	case "add-principals":
		in = "Add principals (users, groups) to"
	case "set-principals":
		in = "Set the full contents of the principals (users, groups) on"
	case "remove-principals":
		in = "Remove principals (users, groups) from"
	}
	return wordwrap.WrapString(fmt.Sprintf("%s a role within Watchtower", in), 80)
}

func baseHelp() string {
	return base.WrapForHelpText([]string{
		"Usage: watchtower role [sub command] [options] [args]",
		"",
		"  This command allows operations on Watchtower roles. Examples:",
		"",
		"    Create a role:",
		"",
		`      $ watchtower role create -name foo -description "For ProdOps usage"`,
		"",
		"    Add a grant to a role:",
		"",
		`      $ watchtower role add-grants -id r_1234567890 -grant "type=host-catalog;actions=create,delete"`,
		"",
		"  Please see the role subcommand help for detailed usage information.",
	})
}

func createHelp(flagHelp string) string {
	return base.WrapForHelpText([]string{
		"Usage: watchtower roles create [options] [args]",
		"",
		"  Create a role. Example:",
		"",
		`    $ watchtower roles create -name ops -description "Role for ops grants"`,
	}) + flagHelp
}

func updateHelp(flagHelp string) string {
	return base.WrapForHelpText([]string{
		"Usage: watchtower roles update [options] [args]",
		"",
		"  Update a role given its ID. Example:",
		"",
		`    $ watchtower roles update -id r_1234567890 -description "Development host grants"`,
	}) + flagHelp
}

func readHelp(flagHelp string) string {
	return base.WrapForHelpText([]string{
		"Usage: watchtower roles read [options] [args]",
		"",
		"  Read a role given its ID. Example:",
		"",
		`    $ watchtower roles read -id r_1234567890`,
	}) + flagHelp
}

func deleteHelp(flagHelp string) string {
	return base.WrapForHelpText([]string{
		"Usage: watchtower roles delete [options] [args]",
		"",
		"  Delete a role given its ID. Example:",
		"",
		`    $ watchtower roles delete -id r_1234567890`,
	}) + flagHelp
}

func listHelp(flagHelp string) string {
	return base.WrapForHelpText([]string{
		"Usage: watchtower roles list [options] [args]",
		"",
		"  List roles within a scope. Example:",
		"",
		`    $ watchtower roles list -org o_1234567890`,
	}) + flagHelp
}

func addPrincipalsHelp(flagHelp string) string {
	return base.WrapForHelpText([]string{
		"Usage: watchtower roles add-principals [options] [args]",
		"",
		`  Adds principals (users, groups) to a role given its ID. The "user" and "group" flags can be specified multiple times. Example:`,
		"",
		`    $ watchtower roles add-principals -id r_1234567890 -user u_1234567890`,
	}) + flagHelp
}

func setPrincipalsHelp(flagHelp string) string {
	return base.WrapForHelpText([]string{
		"Usage: watchtower roles set-principals [options] [args]",
		"",
		`  Sets the complete set of principals (users, groups) on a role given its ID. The "user" and "group" flags can be specified multiple times. Example:`,
		"",
		`    $ watchtower roles set-principals -id r_1234567890 -user u_anon -group sg_1234567890`,
	}) + flagHelp
}

func removePrincipalsHelp(flagHelp string) string {
	return base.WrapForHelpText([]string{
		"Usage: watchtower roles remove-principals [options] [args]",
		"",
		`  Removes principals (users, groups) from a role given its ID. The "user" and "group" flags can be specified multiple times. Example:`,
		"",
		`    $ watchtower roles remove-principals -id r_1234567890 -group sg_1234567890`,
	}) + flagHelp
}

func populateFlags(c *Command, f *base.FlagSet, flagNames []string) {
	for _, name := range flagNames {
		switch name {
		case "id":
			f.StringVar(&base.StringVar{
				Name:   "id",
				Target: &c.flagId,
				Usage:  "ID of the role to operate on",
			})
		case "name":
			f.StringVar(&base.StringVar{
				Name:   "name",
				Target: &c.flagName,
				Usage:  "Name to set on the role",
			})
		case "description":
			f.StringVar(&base.StringVar{
				Name:   "description",
				Target: &c.flagDescription,
				Usage:  "Description to set on the role",
			})
		case "grantscopeid":
			f.StringVar(&base.StringVar{
				Name:   "grant-scope-id",
				Target: &c.flagGrantScopeId,
				Usage:  "The scope ID for grants set on the role",
			})
		case "user":
			f.StringSliceVar(&base.StringSliceVar{
				Name:   "user",
				Target: &c.flagUsers,
				Usage:  "The users to add, remove, or set. May be specified multiple times",
			})
		case "group":
			f.StringSliceVar(&base.StringSliceVar{
				Name:   "group",
				Target: &c.flagGroups,
				Usage:  "The groups to add, remove, or set. May be specified multiple times",
			})
		}
	}
}

func generateRoleOutput(role *roles.Role) string {
	var output []string
	if true {
		output = []string{
			"",
			"Role information:",
			fmt.Sprintf("  ID:             %s", role.Id),
			fmt.Sprintf("  Created At:     %s", role.CreatedTime.Local().Format(time.RFC3339)),
			fmt.Sprintf("  Updated At:     %s", role.UpdatedTime.Local().Format(time.RFC3339)),
			fmt.Sprintf("  Version:        %d", role.Version),
		}
	}
	if role.Name != nil {
		output = append(output,
			fmt.Sprintf("  Name:           %s", *role.Name),
		)
	}
	if role.Description != nil {
		output = append(output,
			fmt.Sprintf("  Description:    %s", *role.Description),
		)
	}
	if role.GrantScopeId != nil {
		output = append(output,
			fmt.Sprintf("  Grant Scope ID: %s", *role.GrantScopeId),
		)
	}
	if len(role.UserIds) > 0 {
		output = append(output,
			fmt.Sprintf("  Users:          %s", strings.Join(role.UserIds, ", ")),
		)
	}
	if len(role.GroupIds) > 0 {
		output = append(output,
			fmt.Sprintf("  Groups:         %s", strings.Join(role.GroupIds, ", ")),
		)
	}
	return base.WrapForHelpText(output)
}
