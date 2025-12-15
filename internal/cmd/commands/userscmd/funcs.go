// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package userscmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/users"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/mitchellh/go-wordwrap"
)

func init() {
	extraActionsFlagsMapFunc = extraActionsFlagsMapFuncImpl
	extraSynopsisFunc = extraSynopsisFuncImpl
	extraFlagsFunc = extraFlagsFuncImpl
	extraFlagsHandlingFunc = extraFlagsHandlingFuncImpl
	executeExtraActions = executeExtraActionsImpl
}

type extraCmdVars struct {
	flagAccounts []string
}

func extraActionsFlagsMapFuncImpl() map[string][]string {
	return map[string][]string{
		"add-accounts":    {"id", "account", "version"},
		"set-accounts":    {"id", "account", "version"},
		"remove-accounts": {"id", "account", "version"},
	}
}

func extraSynopsisFuncImpl(c *Command) string {
	switch c.Func {
	case "add-accounts", "set-accounts", "remove-accounts":
		var in string
		switch {
		case strings.HasPrefix(c.Func, "add"):
			in = "Add accounts to"
		case strings.HasPrefix(c.Func, "set"):
			in = "Set the full contents of the accounts on"
		case strings.HasPrefix(c.Func, "remove"):
			in = "Remove accounts from"
		}
		return wordwrap.WrapString(fmt.Sprintf("%s a user within Boundary", in), base.TermWidth)
	}

	return ""
}

func (c *Command) extraHelpFunc(helpMap map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "add-accounts":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary users add-accounts [options] [args]",
			"",
			`  Associates accounts to a user given its ID. The "account" flag can be specified multiple times. Example:`,
			"",
			`    $ boundary users add-accounts -id u_1234567890 -account a_1234567890`,
			"",
			"",
		})

	case "set-accounts":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary users set-accounts [options] [args]",
			"",
			`  Sets the complete set of associated accounts on a user given its ID. The "account" flag can be specified multiple times. Example:`,
			"",
			`    $ boundary users set-principals -id u_1234567890 -account a_0987654321 -account a_1234567890`,
			"",
			"",
		})

	case "remove-accounts":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary users remove-accounts [options] [args]",
			"",
			`  Disassociates accounts from a user given its ID. The "account" flag can be specified multiple times. Example:`,
			"",
			`    $ boundary users remove-accounts -id u_1234567890 -account a_1234567890`,
			"",
			"",
		})

	default:
		helpStr = helpMap["base"]()
	}
	return helpStr + c.Flags().Help()
}

func extraFlagsFuncImpl(c *Command, _ *base.FlagSets, f *base.FlagSet) {
	for _, name := range flagsMap[c.Func] {
		switch name {
		case "account":
			f.StringSliceVar(&base.StringSliceVar{
				Name:   "account",
				Target: &c.flagAccounts,
				Usage:  "The accounts to add, remove, or set. May be specified multiple times.",
			})
		}
	}
}

func extraFlagsHandlingFuncImpl(c *Command, _ *base.FlagSets, opts *[]users.Option) bool {
	switch c.Func {
	case "add-accounts", "remove-accounts":
		if len(c.flagAccounts) == 0 {
			c.UI.Error("No accounts supplied via -account")
			return false
		}

	case "set-accounts":
		switch len(c.flagAccounts) {
		case 0:
			c.UI.Error("No accounts supplied via -account")
			return false
		case 1:
			if c.flagAccounts[0] == "null" {
				c.flagAccounts = nil
			}
		}
	}

	return true
}

func executeExtraActionsImpl(c *Command, origResp *api.Response, origItem *users.User, origItems []*users.User, origError error, userClient *users.Client, version uint32, opts []users.Option) (*api.Response, *users.User, []*users.User, error) {
	switch c.Func {
	case "add-accounts":
		result, err := userClient.AddAccounts(c.Context, c.FlagId, version, c.flagAccounts, opts...)
		if err != nil {
			return nil, nil, nil, err
		}
		return result.GetResponse(), result.GetItem(), nil, err
	case "set-accounts":
		result, err := userClient.SetAccounts(c.Context, c.FlagId, version, c.flagAccounts, opts...)
		if err != nil {
			return nil, nil, nil, err
		}
		return result.GetResponse(), result.GetItem(), nil, err
	case "remove-accounts":
		result, err := userClient.RemoveAccounts(c.Context, c.FlagId, version, c.flagAccounts, opts...)
		if err != nil {
			return nil, nil, nil, err
		}
		return result.GetResponse(), result.GetItem(), nil, err
	}
	return origResp, origItem, origItems, origError
}

func (c *Command) printListTable(items []*users.User) string {
	if len(items) == 0 {
		return "No users found"
	}

	var output []string
	output = []string{
		"",
		"User information:",
	}

	for i, item := range items {
		if i > 0 {
			output = append(output, "")
		}
		if item.Id != "" {
			output = append(output,
				fmt.Sprintf("  ID:                    %s", item.Id),
			)
		} else {
			output = append(output,
				fmt.Sprintf("  ID:                    %s", "(not available)"),
			)
		}
		if c.FlagRecursive && item.ScopeId != "" {
			output = append(output,
				fmt.Sprintf("    Scope ID:            %s", item.ScopeId),
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
		if item.PrimaryAccountId != "" {
			output = append(output,
				fmt.Sprintf("    Primary Account ID:  %s", item.PrimaryAccountId),
			)
		}
		if item.LoginName != "" {
			output = append(output,
				fmt.Sprintf("    Login Name:          %s", item.LoginName),
			)
		}
		if item.FullName != "" {
			output = append(output,
				fmt.Sprintf("    Full Name:           %s", item.FullName),
			)
		}
		if item.Email != "" {
			output = append(output,
				fmt.Sprintf("    Email:               %s", item.Email),
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

func printItemTable(item *users.User, resp *api.Response) string {
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
	if item.PrimaryAccountId != "" {
		nonAttributeMap["Primary Account Id"] = item.PrimaryAccountId
	}
	if item.LoginName != "" {
		nonAttributeMap["Login Name"] = item.LoginName
	}
	if item.FullName != "" {
		nonAttributeMap["Full Name"] = item.FullName
	}
	if item.Email != "" {
		nonAttributeMap["Email"] = item.Email
	}

	maxLength := base.MaxAttributesLength(nonAttributeMap, nil, nil)

	var userMaps []map[string]any
	if len(item.Accounts) > 0 {
		for _, account := range item.Accounts {
			a := map[string]any{
				"ID":       account.Id,
				"Scope ID": account.ScopeId,
			}
			userMaps = append(userMaps, a)
		}
		if l := len("Scope ID"); l > maxLength {
			maxLength = l
		}
	}

	ret := []string{
		"",
		"User information:",
		base.WrapMap(2, maxLength+2, nonAttributeMap),
	}

	if item.Scope != nil {
		ret = append(ret,
			"",
			"  Scope:",
			base.ScopeInfoForOutput(item.Scope, maxLength),
		)
	}

	if len(item.AuthorizedActions) > 0 {
		ret = append(ret,
			"",
			"  Authorized Actions:",
			base.WrapSlice(4, item.AuthorizedActions),
		)
	}

	if len(item.Accounts) > 0 {
		ret = append(ret,
			"",
			"  Accounts:",
		)
		for _, m := range userMaps {
			ret = append(ret,
				base.WrapMap(4, maxLength, m),
				"",
			)
		}
	}

	return base.WrapForHelpText(ret)
}
