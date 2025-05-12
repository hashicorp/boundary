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
	"github.com/hashicorp/boundary/version"
)

const (
	flagPrimaryAuthMethodIdName     = "primary-auth-method-id"
	flagSkipAdminRoleCreationName   = "skip-admin-role-creation"
	flagSkipDefaultRoleCreationName = "skip-default-role-creation"
	flagCreateAdminRoleName         = "create-admin-role"
	flagCreateDefaultRoleName       = "create-default-role"
	flagStoragePolicyIdName         = "storage-policy-id"
)

func init() {
	extraActionsFlagsMapFunc = extraActionsFlagsMapFuncImpl
	extraFlagsFunc = extraFlagsFuncImpl
	extraFlagsHandlingFunc = extraFlagsHandlingFuncImpl
	executeExtraActions = executeExtraActionsImpl
}

func extraActionsFlagsMapFuncImpl() map[string][]string {
	extraActionsFlagsMap := map[string][]string{
		"update":                {flagPrimaryAuthMethodIdName},
		"attach-storage-policy": {"id", "version", flagStoragePolicyIdName},
		"detach-storage-policy": {"id", "version"},
	}
	if version.SupportsFeature(version.Binary, version.CreateDefaultAndAdminRoles) {
		extraActionsFlagsMap["create"] = append(extraActionsFlagsMap["create"], flagCreateAdminRoleName, flagCreateDefaultRoleName)
	}
	if version.SupportsFeature(version.Binary, version.SkipDefaultAndAdminRoleCreation) {
		extraActionsFlagsMap["create"] = append(extraActionsFlagsMap["create"], flagSkipAdminRoleCreationName, flagSkipDefaultRoleCreationName)
	}
	return extraActionsFlagsMap
}

type extraCmdVars struct {
	flagSkipAdminRoleCreation   bool
	flagSkipDefaultRoleCreation bool
	flagCreateAdminRole         bool
	flagCreateDefaultRole       bool
	flagPrimaryAuthMethodId     string
	flagStoragePolicyId         string
}

func extraFlagsFuncImpl(c *Command, set *base.FlagSets, f *base.FlagSet) {
	for _, name := range flagsMap[c.Func] {
		switch name {
		case flagSkipAdminRoleCreationName:
			f.BoolVar(&base.BoolVar{
				Name:   flagSkipAdminRoleCreationName,
				Target: &c.flagSkipAdminRoleCreation,
				Usage:  "Deprecated: If set, a role granting the current user access to administer the newly-created scope will not automatically be created",
			})
		case flagSkipDefaultRoleCreationName:
			f.BoolVar(&base.BoolVar{
				Name:   flagSkipDefaultRoleCreationName,
				Target: &c.flagSkipDefaultRoleCreation,
				Usage:  "Deprecated: If set, a role granting the anonymous user access to log into auth methods and a few other actions within the newly-created scope will not automatically be created",
			})
		case flagPrimaryAuthMethodIdName:
			f.StringVar(&base.StringVar{
				Name:   flagPrimaryAuthMethodIdName,
				Target: &c.flagPrimaryAuthMethodId,
				Usage:  "If set, the primary auth method id for the scope.  A primary auth method is allowed to create users on first login and is also used as a source for account full name and email for a scope's users",
			})
		case flagStoragePolicyIdName:
			f.StringVar(&base.StringVar{
				Name:   flagStoragePolicyIdName,
				Target: &c.flagStoragePolicyId,
				Usage:  "The public ID of the Storage Policy to attach to this scope. Can only attach to the global scope and an Org scope.",
			})
		case flagCreateAdminRoleName:
			f.BoolVar(&base.BoolVar{
				Name:   flagCreateAdminRoleName,
				Target: &c.flagCreateAdminRole,
				Usage:  "If set, a role granting the current user access to administer the newly-created scope will automatically be created",
			})
		case flagCreateDefaultRoleName:
			f.BoolVar(&base.BoolVar{
				Name:   flagCreateDefaultRoleName,
				Target: &c.flagCreateDefaultRole,
				Usage:  "If set, a role granting the anonymous user access to log into auth methods and a few other actions within the newly-created scope will automatically be created",
			})
		}
	}
}

func extraFlagsHandlingFuncImpl(c *Command, _ *base.FlagSets, opts *[]scopes.Option) bool {
	// Validate inputs
	switch c.Func {
	case "attach-storage-policy":
		if len(c.flagStoragePolicyId) == 0 {
			c.UI.Error("No storage policy ID supplied via -storage-policy-id")
			return false
		}
	}

	if version.SupportsFeature(version.Binary, version.CreateDefaultAndAdminRoles) {
		if c.flagCreateAdminRole && c.flagSkipAdminRoleCreation {
			c.UI.Error("Cannot set both --create-admin-role and --skip-admin-role-creation to true")
		}
		if c.flagCreateDefaultRole && c.flagSkipDefaultRoleCreation {
			c.UI.Error("Cannot set both --create-default-role and --skip-default-role-creation to true")
		}
		if !c.flagCreateAdminRole && !c.flagSkipAdminRoleCreation {
			c.UI.Output("Warning: --skip-admin-role-creation is deprecated and will be removed in a future version. Use --create-admin-role instead.")
			*opts = append(*opts, scopes.WithSkipAdminRoleCreation(!c.flagSkipAdminRoleCreation))
		}
		if !c.flagCreateDefaultRole && !c.flagSkipDefaultRoleCreation {
			c.UI.Output("Warning: --skip-default-role-creation is deprecated and will be removed in a future version. Use --create-default-role instead.")
			*opts = append(*opts, scopes.WithSkipDefaultRoleCreation(!c.flagSkipDefaultRoleCreation))
		}
		if c.flagCreateAdminRole {
			*opts = append(*opts, scopes.WithCreateAdminRole(c.flagCreateAdminRole))
		}
		if c.flagCreateDefaultRole {
			*opts = append(*opts, scopes.WithCreateDefaultRole(c.flagCreateDefaultRole))
		}
	}

	if version.SupportsFeature(version.Binary, version.SkipDefaultAndAdminRoleCreation) {
		if c.flagSkipAdminRoleCreation {
			*opts = append(*opts, scopes.WithSkipAdminRoleCreation(c.flagSkipAdminRoleCreation))
		}
		if c.flagSkipDefaultRoleCreation {
			*opts = append(*opts, scopes.WithSkipDefaultRoleCreation(c.flagSkipDefaultRoleCreation))
		}
	}

	if c.flagPrimaryAuthMethodId != "" {
		*opts = append(*opts, scopes.WithPrimaryAuthMethodId(c.flagPrimaryAuthMethodId))
	}

	return true
}

func executeExtraActionsImpl(c *Command, origResp *api.Response, origItem *scopes.Scope, origItems []*scopes.Scope, origError error, scopeClient *scopes.Client, version uint32, opts []scopes.Option) (*api.Response, *scopes.Scope, []*scopes.Scope, error) {
	switch c.Func {
	case "attach-storage-policy":
		result, err := scopeClient.AttachStoragePolicy(c.Context, c.FlagId, version, c.flagStoragePolicyId, opts...)
		if err != nil {
			return nil, nil, nil, err
		}
		return result.GetResponse(), result.GetItem(), nil, err
	case "detach-storage-policy":
		result, err := scopeClient.DetachStoragePolicy(c.Context, c.FlagId, version, opts...)
		if err != nil {
			return nil, nil, nil, err
		}
		return result.GetResponse(), result.GetItem(), nil, err
	}
	return origResp, origItem, origItems, origError
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
		if item.StoragePolicyId != "" {
			output = append(output,
				fmt.Sprintf("    StoragePolicyId:     %s", item.StoragePolicyId),
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
	if item.StoragePolicyId != "" {
		nonAttributeMap["Storage Policy ID"] = item.StoragePolicyId
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

func (c *Command) extraHelpFunc(_ map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "attach-storage-policy":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary scopes attach-storage-policy [options] [args]",
			"",
			"  This command allows attaching a storage policy to scope resources. Example:",
			"",
			"    Attach storage policy to a scope:",
			"",
			`      $ boundary scopes attach-storage-policy -id o_1234567890 -storage-policy-id pst_1234567890`,
			"",
			"",
		})
	case "detach-storage-policy":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary scope detach-storage-policy [options] [args]",
			"",
			"  This command allows detaching a storage policy from scope resources. Example:",
			"",
			"    Detach storage policy from scope:",
			"",
			`      $ boundary scopes detach-storage-policy -id o_1234567890`,
			"",
			"",
		})
	}
	return helpStr + c.Flags().Help()
}
