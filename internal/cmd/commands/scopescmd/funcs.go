// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package scopescmd

import (
	"fmt"
	"sort"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

const (
	flagPrimaryAuthMethodIdName     = "primary-auth-method-id"
	flagSkipAdminRoleCreationName   = "skip-admin-role-creation"
	flagSkipDefaultRoleCreationName = "skip-default-role-creation"
)

func init() {
	extraActionsFlagsMapFunc = extraActionsFlagsMapFuncImpl
	extraFlagsFunc = extraFlagsFuncImpl
	extraFlagsHandlingFunc = extraFlagsHandlingFuncImpl
}

func extraActionsFlagsMapFuncImpl() map[string][]string {
	return map[string][]string{
		"create": {flagSkipAdminRoleCreationName, flagSkipDefaultRoleCreationName},
		"update": {flagPrimaryAuthMethodIdName},
	}
}

type extraCmdVars struct {
	flagSkipAdminRoleCreation   bool
	flagSkipDefaultRoleCreation bool
	flagPrimaryAuthMethodId     string
}

func extraFlagsFuncImpl(c *Command, set *base.FlagSets, f *base.FlagSet) {
	for _, name := range flagsMap[c.Func] {
		switch name {
		case flagSkipAdminRoleCreationName:
			f.BoolVar(&base.BoolVar{
				Name:   flagSkipAdminRoleCreationName,
				Target: &c.flagSkipAdminRoleCreation,
				Usage:  "If set, a role granting the current user access to administer the newly-created scope will not automatically be created",
			})
		case flagSkipDefaultRoleCreationName:
			f.BoolVar(&base.BoolVar{
				Name:   flagSkipDefaultRoleCreationName,
				Target: &c.flagSkipDefaultRoleCreation,
				Usage:  "If set, a role granting the anonymous user access to log into auth methods and a few other actions within the newly-created scope will not automatically be created",
			})
		case flagPrimaryAuthMethodIdName:
			f.StringVar(&base.StringVar{
				Name:   flagPrimaryAuthMethodIdName,
				Target: &c.flagPrimaryAuthMethodId,
				Usage:  "If set, the primary auth method id for the scope.  A primary auth method is allowed to create users on first login and is also used as a source for account full name and email for a scope's users",
			})
		}
	}
}

func extraFlagsHandlingFuncImpl(c *Command, _ *base.FlagSets, opts *[]scopes.Option) bool {
	if c.flagSkipAdminRoleCreation {
		*opts = append(*opts, scopes.WithSkipAdminRoleCreation(c.flagSkipAdminRoleCreation))
	}
	if c.flagSkipDefaultRoleCreation {
		*opts = append(*opts, scopes.WithSkipDefaultRoleCreation(c.flagSkipDefaultRoleCreation))
	}
	if c.flagPrimaryAuthMethodId != "" {
		*opts = append(*opts, scopes.WithPrimaryAuthMethodId(c.flagPrimaryAuthMethodId))
	}

	return true
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
		if item.PrimaryAuthMethodId != "" {
			output = append(output,
				fmt.Sprintf("    PrimaryAuthMethodId: %s", item.PrimaryAuthMethodId),
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

func printItemTable(item *scopes.Scope, resp *api.Response) string {
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
	if item.PrimaryAuthMethodId != "" {
		nonAttributeMap["Primary Auth Method ID"] = item.PrimaryAuthMethodId
	}

	maxLength := base.MaxAttributesLength(nonAttributeMap, nil, nil)

	ret := []string{
		"",
		"Scope information:",
		base.WrapMap(2, maxLength+2, nonAttributeMap),
	}

	if item.Scope != nil {
		ret = append(ret,
			"",
			"  Scope (parent):",
			base.ScopeInfoForOutput(item.Scope, maxLength),
		)
	}

	if len(item.AuthorizedActions) > 0 {
		ret = append(ret,
			"",
			"  Authorized Actions:",
			base.WrapSlice(4, item.AuthorizedActions),
			"",
		)
	}

	if len(item.AuthorizedCollectionActions) > 0 {
		keys := make([]string, 0, len(item.AuthorizedCollectionActions))
		for k := range item.AuthorizedCollectionActions {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		ret = append(ret, "  Authorized Actions on Scope's Collections:")
		for _, key := range keys {
			ret = append(ret,
				fmt.Sprintf("    %s:", key),
				base.WrapSlice(6, item.AuthorizedCollectionActions[key]),
			)
		}
	}

	return base.WrapForHelpText(ret)
}
