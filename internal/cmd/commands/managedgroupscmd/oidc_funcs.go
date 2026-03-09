// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package managedgroupscmd

import (
	"fmt"

	"github.com/hashicorp/boundary/api/managedgroups"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/go-bexpr"
)

const (
	filterFlagName = "filter"
)

func init() {
	extraOidcFlagsFunc = extraOidcFlagsFuncImpl
	extraOidcActionsFlagsMapFunc = extraOidcActionsFlagsMapFuncImpl
	extraOidcFlagsHandlingFunc = extraOidcFlagsHandlingFuncImpl
}

func extraOidcActionsFlagsMapFuncImpl() map[string][]string {
	return map[string][]string{
		"create": {filterFlagName},
		"update": {filterFlagName},
	}
}

type extraOidcCmdVars struct {
	flagFilter string
}

func (c *OidcCommand) extraOidcHelpFunc(helpMap map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary managed-groups create oidc [options] [args]",
			"",
			"  Create a oidc-type managed group. Example:",
			"",
			`    $ boundary managed-groups create oidc -filter '"/token/email" == "doe@example.com"' -description "Oidc managed group for ProdOps"`,
			"",
			"",
		})

	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary managed-groups update oidc [options] [args]",
			"",
			"  Update a oidc-type managed group given its ID. Example:",
			"",
			`    $ boundary managed-groups update oidc -id acctoidc_1234567890 -name "devops" -description "Oidc managed group for DevOps"`,
			"",
			"",
		})
	}
	return helpStr + c.Flags().Help()
}

func extraOidcFlagsFuncImpl(c *OidcCommand, _ *base.FlagSets, f *base.FlagSet) {
	for _, name := range flagsOidcMap[c.Func] {
		switch name {
		case "filter":
			f.StringVar(&base.StringVar{
				Name:   filterFlagName,
				Target: &c.flagFilter,
				Usage:  "The filter defining the criteria against which an accounts's OIDC token and/or userinfo will be evaluated to determined membership at login time.",
			})
		}
	}
}

func extraOidcFlagsHandlingFuncImpl(c *OidcCommand, _ *base.FlagSets, opts *[]managedgroups.Option) bool {
	switch c.flagFilter {
	case "null":
		c.UI.Error("Filter must be defined, and cannot be cleared.")
		return false

	case "":
		if c.Func == "create" {
			c.UI.Error("The -filter flag must be provided when creating a managed group.")
			return false
		}

	default:
		_, err := bexpr.CreateEvaluator(c.flagFilter)
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error when parsing filter to check validity: %v", err))
			return false
		}
		*opts = append(*opts, managedgroups.WithAttributes(map[string]any{filterFlagName: c.flagFilter}))
	}

	return true
}
