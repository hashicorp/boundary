// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package accountscmd

import (
	"github.com/hashicorp/boundary/api/accounts"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

const (
	loginNameFlagName = "login-name"
)

func init() {
	extraLdapActionsFlagsMapFunc = extraLdapActionsFlagsMapFuncImpl
	extraLdapFlagsFunc = extraLdapFlagsFuncImpl
	extraLdapFlagsHandlingFunc = extraLdapFlagsHandlingFuncImpl
}

func extraLdapActionsFlagsMapFuncImpl() map[string][]string {
	return map[string][]string{
		"create": {loginNameFlagName},
	}
}

type extraLdapCmdVars struct {
	flagLoginName string
}

func (c *LdapCommand) extraLdapHelpFunc(helpMap map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary accounts create ldap [options] [args]",
			"",
			"  Create an ldap-type account. Example:",
			"",
			`    $ boundary accounts create ldap -login-name prodops -description "ldap account for ProdOps"`,
			"",
			"",
		})

	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary accounts update ldap [options] [args]",
			"",
			"  Update an ldap-type account given its ID. Example:",
			"",
			`    $ boundary accounts update ldap -id acctldap_1234567890 -name "devops" -description "ldap account for DevOps"`,
			"",
			"",
		})
	}
	return helpStr + c.Flags().Help()
}

func extraLdapFlagsFuncImpl(c *LdapCommand, set *base.FlagSets, _ *base.FlagSet) {
	f := set.NewFlagSet("Ldap Account Options")

	for _, name := range flagsLdapMap[c.Func] {
		switch name {
		case loginNameFlagName:
			f.StringVar(&base.StringVar{
				Name:   loginNameFlagName,
				Target: &c.flagLoginName,
				Usage:  "The login name for the account.",
			})
		}
	}
}

func extraLdapFlagsHandlingFuncImpl(c *LdapCommand, _ *base.FlagSets, opts *[]accounts.Option) bool {
	switch c.flagLoginName {
	case "null", "":
		if c.Func == "create" {
			c.UI.Error("Login-name must be passed in via -login-name")
			return false
		}
	default:
		if c.Func != "create" {
			c.UI.Error("-login-name can only be set when creating an ldap account")
			return false
		}
		*opts = append(*opts, accounts.WithLdapAccountLoginName(c.flagLoginName))
	}
	return true
}
