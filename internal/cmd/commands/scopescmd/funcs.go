package scopescmd

import (
	"fmt"
	"sort"
	"time"

	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func init() {
	extraActionsFlagsMapFunc = extraActionsFlagsMapFuncImpl
	extraFlagsFunc = extraFlagsFuncImpl
	extraFlagsHandlingFunc = extraFlagsHandlingFuncImpl
}

func extraActionsFlagsMapFuncImpl() map[string][]string {
	return map[string][]string{
		"create": {"skip-admin-role-creation", "skip-default-role-creation"},
	}
}

type extraCmdVars struct {
	flagSkipAdminRoleCreation   bool
	flagSkipDefaultRoleCreation bool
}

func extraFlagsFuncImpl(c *Command, set *base.FlagSets, f *base.FlagSet) {
	for _, name := range flagsMap[c.Func] {
		switch name {
		case "skip-admin-role-creation":
			f.BoolVar(&base.BoolVar{
				Name:   "skip-admin-role-creation",
				Target: &c.flagSkipAdminRoleCreation,
				Usage:  "If set, a role granting the current user access to administer the newly-created scope will not automatically be created",
			})
		case "skip-default-role-creation":
			f.BoolVar(&base.BoolVar{
				Name:   "skip-default-role-creation",
				Target: &c.flagSkipDefaultRoleCreation,
				Usage:  "If set, a role granting the anonymous user access to log into auth methods and a few other actions within the newly-created scope will not automatically be created",
			})
		}
	}
}

func extraFlagsHandlingFuncImpl(c *Command, opts *[]scopes.Option) int {
	if c.flagSkipAdminRoleCreation {
		*opts = append(*opts, scopes.WithSkipAdminRoleCreation(c.flagSkipAdminRoleCreation))
	}
	if c.flagSkipDefaultRoleCreation {
		*opts = append(*opts, scopes.WithSkipDefaultRoleCreation(c.flagSkipDefaultRoleCreation))
	}

	return 0
}

func (c *Command) printListTable(items []*scopes.Scope) string {
	if len(items) == 0 {
		return "No child scopes found"
	}
	var output []string
	output = []string{
		"",
		"Scope information:",
	}
	for i, item := range items {
		if i > 0 {
			output = append(output, "")
		}
		if true {
			output = append(output,
				fmt.Sprintf("  ID:                    %s", item.Id),
			)
		}
		if c.FlagRecursive {
			output = append(output,
				fmt.Sprintf("    Scope ID:            %s", item.Scope.Id),
			)
		}
		if true {
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

func printItemTable(in *scopes.Scope) string {
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

	maxLength := base.MaxAttributesLength(nonAttributeMap, nil, nil)

	ret := []string{
		"",
		"Scope information:",
		base.WrapMap(2, maxLength+2, nonAttributeMap),
		"",
		"  Scope (parent):",
		base.ScopeInfoForOutput(in.Scope, maxLength),
	}

	if len(in.AuthorizedActions) > 0 {
		ret = append(ret,
			"",
			"  Authorized Actions:",
			base.WrapSlice(4, in.AuthorizedActions),
			"",
		)
	}

	if len(in.AuthorizedCollectionActions) > 0 {
		keys := make([]string, 0, len(in.AuthorizedCollectionActions))
		for k := range in.AuthorizedCollectionActions {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		ret = append(ret, "  Authorized Actions on Scope's Collections:")
		for _, key := range keys {
			ret = append(ret,
				fmt.Sprintf("    %s:", key),
				base.WrapSlice(6, in.AuthorizedCollectionActions[key]),
			)
		}
	}

	return base.WrapForHelpText(ret)
}
