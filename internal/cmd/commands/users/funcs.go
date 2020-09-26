package users

import (
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/boundary/api/users"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/common"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/mitchellh/go-wordwrap"
)

func accountSynopsisFunc(inFunc string) string {
	var in string
	switch {
	case strings.HasPrefix(inFunc, "add"):
		in = "Add accounts to"
	case strings.HasPrefix(inFunc, "set"):
		in = "Set the full contents of the accounts on"
	case strings.HasPrefix(inFunc, "remove"):
		in = "Remove accounts from"
	}
	return wordwrap.WrapString(fmt.Sprintf("%s a user within Boundary", in), base.TermWidth)
}

func addAccountsHelp() string {
	return base.WrapForHelpText([]string{
		"Usage: boundary users add-accounts [options] [args]",
		"",
		`  Associates accounts to a user given its ID. The "account" flag can be specified multiple times. Example:`,
		"",
		`    $ boundary users add-accounts -id u_1234567890 -account a_1234567890`,
	})
}

func setAccountsHelp() string {
	return base.WrapForHelpText([]string{
		"Usage: boundary users set-accounts [options] [args]",
		"",
		`  Sets the complete set of associated accounts on a user given its ID. The "account" flag can be specified multiple times. Example:`,
		"",
		`    $ boundary users set-principals -id u_1234567890 -account a_0987654321 -account a_1234567890`,
	})
}

func removeAccountsHelp() string {
	return base.WrapForHelpText([]string{
		"Usage: boundary users remove-accounts [options] [args]",
		"",
		`  Disassociates accounts from a user given its ID. The "account" flag can be specified multiple times. Example:`,
		"",
		`    $ boundary users remove-accounts -id u_1234567890 -account a_1234567890`,
	})
}

func populateFlags(c *Command, f *base.FlagSet, flagNames []string) {
	common.PopulateCommonFlags(c.Command, f, resource.User.String(), flagNames)

	for _, name := range flagNames {
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

func generateUserTableOutput(in *users.User) string {
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
