// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package accountscmd

import (
	"github.com/hashicorp/boundary/api/accounts"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

const (
	subjectFlagName = "subject"
	issuerFlagName  = "issuer"
)

func init() {
	extraOidcActionsFlagsMapFunc = extraOidcActionsFlagsMapFuncImpl
	extraOidcFlagsFunc = extraOidcFlagsFuncImpl
	extraOidcFlagsHandlingFunc = extraOidcFlagsHandlingFuncImpl
}

func extraOidcActionsFlagsMapFuncImpl() map[string][]string {
	return map[string][]string{
		"create": {subjectFlagName, issuerFlagName},
	}
}

type extraOidcCmdVars struct {
	flagIssuer  string
	flagSubject string
}

func (c *OidcCommand) extraOidcHelpFunc(helpMap map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary accounts create oidc [options] [args]",
			"",
			"  Create a oidc-type account. Example:",
			"",
			`    $ boundary accounts create oidc -subject "prodops" -description "Oidc account for ProdOps"`,
			"",
			"",
		})

	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary accounts update oidc [options] [args]",
			"",
			"  Update a oidc-type account given its ID. Example:",
			"",
			`    $ boundary accounts update oidc -id acctoidc_1234567890 -name "devops" -description "Oidc account for DevOps"`,
			"",
			"",
		})
	}
	return helpStr + c.Flags().Help()
}

func extraOidcFlagsFuncImpl(c *OidcCommand, set *base.FlagSets, _ *base.FlagSet) {
	f := set.NewFlagSet("Oidc Account Options")

	for _, name := range flagsOidcMap[c.Func] {
		switch name {
		case issuerFlagName:
			f.StringVar(&base.StringVar{
				Name:   issuerFlagName,
				Target: &c.flagIssuer,
				Usage:  "The issuer for the account.",
			})
		case subjectFlagName:
			f.StringVar(&base.StringVar{
				Name:   subjectFlagName,
				Target: &c.flagSubject,
				Usage:  "The subject for this account on the OIDC provider.",
			})
		}
	}
}

func extraOidcFlagsHandlingFuncImpl(c *OidcCommand, _ *base.FlagSets, opts *[]accounts.Option) bool {
	switch c.flagSubject {
	case "null", "":
		if c.Func == "create" {
			c.UI.Error("Subject must be passed in via -subject")
			return false
		}
	default:
		if c.Func != "create" {
			c.UI.Error("-subject can only be set when creating an oidc account")
			return false
		}
		*opts = append(*opts, accounts.WithOidcAccountSubject(c.flagSubject))
	}

	switch c.flagIssuer {
	case "":
	case "null":
	default:
		if c.Func != "create" {
			c.UI.Error("-issuer can only be set when creating an oidc account")
			return false
		}
		*opts = append(*opts, accounts.WithOidcAccountIssuer(c.flagIssuer))
	}
	return true
}
