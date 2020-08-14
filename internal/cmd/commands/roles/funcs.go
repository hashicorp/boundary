package roles

import (
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/boundary/api/roles"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/common"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/mitchellh/go-wordwrap"
)

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
	return wordwrap.WrapString(fmt.Sprintf("%s a role within Boundary", in), base.TermWidth)
}

func addPrincipalsHelp() string {
	return base.WrapForHelpText([]string{
		"Usage: boundary roles add-principals [options] [args]",
		"",
		`  Adds principals (users, groups) to a role given its ID. The "principal" flag can be specified multiple times. Example:`,
		"",
		`    $ boundary roles add-principals -id r_1234567890 -principal u_1234567890`,
	})
}

func setPrincipalsHelp() string {
	return base.WrapForHelpText([]string{
		"Usage: boundary roles set-principals [options] [args]",
		"",
		`  Sets the complete set of principals (users, groups) on a role given its ID. The "principal" flag can be specified multiple times. Example:`,
		"",
		`    $ boundary roles set-principals -id r_1234567890 -principal u_anon -principal sg_1234567890`,
	})
}

func removePrincipalsHelp() string {
	return base.WrapForHelpText([]string{
		"Usage: boundary roles remove-principals [options] [args]",
		"",
		`  Removes principals (users, groups) from a role given its ID. The "principal" flags can be specified multiple times. Example:`,
		"",
		`    $ boundary roles remove-principals -id r_1234567890 -principal sg_1234567890`,
	})
}

func populateFlags(c *Command, f *base.FlagSet, flagNames []string) {
	common.PopulateCommonFlags(c.Command, f, resource.Role, flagNames)

	for _, name := range flagNames {
		switch name {
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
			fmt.Sprintf("  ID:               %s", role.Id),
			fmt.Sprintf("  Version:          %d", role.Version),
			fmt.Sprintf("  Created At:       %s", role.CreatedTime.Local().Format(time.RFC3339)),
			fmt.Sprintf("  Updated At:       %s", role.UpdatedTime.Local().Format(time.RFC3339)),
		}
	}
	if role.Name != "" {
		output = append(output,
			fmt.Sprintf("  Name:             %s", role.Name),
		)
	}
	if role.Description != "" {
		output = append(output,
			fmt.Sprintf("  Description:      %s", role.Description),
		)
	}
	if role.GrantScopeId != "" {
		output = append(output,
			fmt.Sprintf("  Grant Scope ID:   %s", role.GrantScopeId),
		)
	}
	if len(role.Principals) > 0 {
		output = append(output,
			fmt.Sprintf("  Principals:       %s", ""),
		)
	}
	for _, principal := range role.Principals {
		output = append(output,
			fmt.Sprintf("    ID:             %s", principal.Id),
			fmt.Sprintf("      Type:         %s", principal.Type),
			fmt.Sprintf("      Scope ID:     %s", principal.ScopeId),
		)
	}
	if len(role.Grants) > 0 {
		output = append(output,
			fmt.Sprintf("  Canonical Grants: %s", ""),
		)
	}
	for _, grant := range role.Grants {
		output = append(output,
			fmt.Sprintf("    %s", grant.Canonical),
		)

	}
	return base.WrapForHelpText(output)
}
