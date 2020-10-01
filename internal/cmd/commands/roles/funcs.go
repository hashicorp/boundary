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
	common.PopulateCommonFlags(c.Command, f, resource.Role.String(), flagNames)

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

func generateRoleTableOutput(in *roles.Role) string {
	nonAttributeMap := map[string]interface{}{
		"ID":           in.Id,
		"Version":      in.Version,
		"Created Time": in.CreatedTime.Local().Format(time.RFC1123),
		"Updated Time": in.UpdatedTime.Local().Format(time.RFC1123),
	}

	if in.Name != "" {
		nonAttributeMap["Name"] = in.Name
	}
	if in.Description != "" {
		nonAttributeMap["Description"] = in.Description
	}
	if in.GrantScopeId != "" {
		nonAttributeMap["Grant Scope ID"] = in.GrantScopeId
	}

	maxLength := base.MaxAttributesLength(nonAttributeMap, nil, nil)

	ret := []string{
		"",
		"Role information:",
		base.WrapMap(2, maxLength+2, nonAttributeMap),
		"",
		"  Scope:",
		base.ScopeInfoForOutput(in.Scope, maxLength),
	}

	if len(in.Principals) > 0 {
		ret = append(ret,
			"",
			fmt.Sprintf("  Principals:       %s", ""),
		)
	}
	for _, principal := range in.Principals {
		ret = append(ret,
			fmt.Sprintf("    ID:             %s", principal.Id),
			fmt.Sprintf("      Type:         %s", principal.Type),
			fmt.Sprintf("      Scope ID:     %s", principal.ScopeId),
		)
	}
	if len(in.Grants) > 0 {
		ret = append(ret,
			"",
			fmt.Sprintf("  Canonical Grants: %s", ""),
		)
	}
	for _, grant := range in.Grants {
		ret = append(ret,
			fmt.Sprintf("    %s", grant.Canonical),
		)

	}
	return base.WrapForHelpText(ret)
}
