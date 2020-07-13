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
		return wordwrap.WrapString("Manage Watchtower roles", base.TermWidth)
	}
	return wordwrap.WrapString(fmt.Sprintf("%s a role within Watchtower", textproto.CanonicalMIMEHeaderKey(inFunc)), base.TermWidth)
}

func principalsGrantsSynopsisFunc(inFunc string, principals bool) string {
	var in string
	switchStr := "principals (users, groups)"
	if !principals {
		switchStr = "grants"
	}
	switch {
	case strings.HasPrefix(inFunc, "add"):
		in = fmt.Sprintf("Add %s to", switchStr)
	case strings.HasPrefix(inFunc, "set"):
		in = fmt.Sprintf("Set the full contents of the %s on", switchStr)
	case strings.HasPrefix(inFunc, "remove"):
		in = fmt.Sprintf("Remove %s from", switchStr)
	}
	return wordwrap.WrapString(fmt.Sprintf("%s a role within Watchtower", in), base.TermWidth)
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

func createHelp() string {
	return base.WrapForHelpText([]string{
		"Usage: watchtower roles create [options] [args]",
		"",
		"  Create a role. Example:",
		"",
		`    $ watchtower roles create -name ops -description "Role for ops grants"`,
		"",
		"",
	})
}

func updateHelp() string {
	return base.WrapForHelpText([]string{
		"Usage: watchtower roles update [options] [args]",
		"",
		"  Update a role given its ID. Example:",
		"",
		`    $ watchtower roles update -id r_1234567890 -description "Development host grants"`,
	})
}

func readHelp() string {
	return base.WrapForHelpText([]string{
		"Usage: watchtower roles read [options] [args]",
		"",
		"  Read a role given its ID. Example:",
		"",
		`    $ watchtower roles read -id r_1234567890`,
	})
}

func deleteHelp() string {
	return base.WrapForHelpText([]string{
		"Usage: watchtower roles delete [options] [args]",
		"",
		"  Delete a role given its ID. Example:",
		"",
		`    $ watchtower roles delete -id r_1234567890`,
	})
}

func listHelp() string {
	return base.WrapForHelpText([]string{
		"Usage: watchtower roles list [options] [args]",
		"",
		"  List roles within a scope. Example:",
		"",
		`    $ watchtower roles list -org o_1234567890`,
	})
}

func addPrincipalsHelp() string {
	return base.WrapForHelpText([]string{
		"Usage: watchtower roles add-principals [options] [args]",
		"",
		`  Adds principals (users, groups) to a role given its ID. The "user" and "group" flags can be specified multiple times. Example:`,
		"",
		`    $ watchtower roles add-principals -id r_1234567890 -user u_1234567890`,
	})
}

func setPrincipalsHelp() string {
	return base.WrapForHelpText([]string{
		"Usage: watchtower roles set-principals [options] [args]",
		"",
		`  Sets the complete set of principals (users, groups) on a role given its ID. The "user" and "group" flags can be specified multiple times. Example:`,
		"",
		`    $ watchtower roles set-principals -id r_1234567890 -user u_anon -group sg_1234567890`,
	})
}

func removePrincipalsHelp() string {
	return base.WrapForHelpText([]string{
		"Usage: watchtower roles remove-principals [options] [args]",
		"",
		`  Removes principals (users, groups) from a role given its ID. The "user" and "group" flags can be specified multiple times. Example:`,
		"",
		`    $ watchtower roles remove-principals -id r_1234567890 -group sg_1234567890`,
	})
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
		case "principal":
			f.StringSliceVar(&base.StringSliceVar{
				Name:   "principal",
				Target: &c.flagPrincipals,
				Usage:  "The principals (users or groups) to add, remove, or set. May be specified multiple times.",
			})
		case "grant":
			f.StringSliceVar(&base.StringSliceVar{
				Name:   "grant",
				Target: &c.flagGrants,
				Usage:  "The grants to add, remove, or set. May be specified multiple times. Can be in compact string format or JSON (be sure to escape JSON properly).",
			})
		}
	}
}

func generateRoleTableOutput(role *roles.Role) string {
	var output []string
	if true {
		output = []string{
			"",
			"Role information:",
			fmt.Sprintf("  ID:                   %s", role.Id),
			fmt.Sprintf("  Created At:           %s", role.CreatedTime.Local().Format(time.RFC3339)),
			fmt.Sprintf("  Updated At:           %s", role.UpdatedTime.Local().Format(time.RFC3339)),
			fmt.Sprintf("  Version:              %d", role.Version),
		}
	}
	if role.Name != nil {
		output = append(output,
			fmt.Sprintf("  Name:                 %s", *role.Name),
		)
	}
	if role.Description != nil {
		output = append(output,
			fmt.Sprintf("  Description:          %s", *role.Description),
		)
	}
	if role.GrantScopeId != nil {
		output = append(output,
			fmt.Sprintf("  Grant Scope ID:       %s", *role.GrantScopeId),
		)
	}
	if len(role.PrincipalIdsScoped) > 0 {
		output = append(output,
			fmt.Sprintf("  Scoped Principal IDs: %s", strings.Join(role.PrincipalIdsScoped, ", ")),
		)
	}
	if len(role.GrantsCanonical) > 0 {
		output = append(output,
			fmt.Sprintf("  Canonical Grants:     %s", strings.Join(role.GrantsCanonical, " | ")),
		)
	}
	return base.WrapForHelpText(output)
}
