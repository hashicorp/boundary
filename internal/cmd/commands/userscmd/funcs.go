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

func executeExtraActionsImpl(c *Command, origResult api.GenericResult, origError error, userClient *users.Client, version uint32, opts []users.Option) (api.GenericResult, error) {
	switch c.Func {
	case "add-accounts":
		return userClient.AddAccounts(c.Context, c.FlagId, version, c.flagAccounts, opts...)
	case "set-accounts":
		return userClient.SetAccounts(c.Context, c.FlagId, version, c.flagAccounts, opts...)
	case "remove-accounts":
		return userClient.RemoveAccounts(c.Context, c.FlagId, version, c.flagAccounts, opts...)
	}
	return origResult, origError
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

	for i, u := range items {
		if i > 0 {
			output = append(output, "")
		}
		if true {
			output = append(output,
				fmt.Sprintf("  ID:                    %s", u.Id),
			)
		}
		if c.FlagRecursive {
			output = append(output,
				fmt.Sprintf("    Scope ID:            %s", u.Scope.Id),
			)
		}
		if true {
			output = append(output,
				fmt.Sprintf("    Version:             %d", u.Version),
			)
		}
		if u.Name != "" {
			output = append(output,
				fmt.Sprintf("    Name:                %s", u.Name),
			)
		}
		if u.Description != "" {
			output = append(output,
				fmt.Sprintf("    Description:         %s", u.Description),
			)
		}
		if u.LoginName != "" {
			output = append(output,
				fmt.Sprintf("    Login Name:          %s", u.LoginName),
			)
		}
		if u.LoginName != "" {
			output = append(output,
				fmt.Sprintf("     Full Name:          %s", u.FullName),
			)
		}
		if u.Email != "" {
			output = append(output,
				fmt.Sprintf("         Email:          %s", u.Email),
			)
		}

		if len(u.AuthorizedActions) > 0 {
			output = append(output,
				"    Authorized Actions:",
				base.WrapSlice(6, u.AuthorizedActions),
			)
		}
	}

	return base.WrapForHelpText(output)
}

func printItemTable(in *users.User) string {
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
	if in.LoginName != "" {
		nonAttributeMap["LoginName"] = in.LoginName
	}
	if in.FullName != "" {
		nonAttributeMap["FullName"] = in.FullName
	}
	if in.Email != "" {
		nonAttributeMap["Email"] = in.Email
	}

	maxLength := base.MaxAttributesLength(nonAttributeMap, nil, nil)

	var userMaps []map[string]interface{}
	if len(in.Accounts) > 0 {
		for _, account := range in.Accounts {
			a := map[string]interface{}{
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
		"",
		"  Scope:",
		base.ScopeInfoForOutput(in.Scope, maxLength),
	}

	if len(in.AuthorizedActions) > 0 {
		ret = append(ret,
			"",
			"  Authorized Actions:",
			base.WrapSlice(4, in.AuthorizedActions),
		)
	}

	if len(in.Accounts) > 0 {
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
