// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package managedgroupscmd

import (
	"fmt"

	"github.com/hashicorp/boundary/api/managedgroups"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

const (
	groupNamesFlagName = "group-names"
)

type extraLdapCmdVars struct {
	flagGroupNames []string
}

func init() {
	extraLdapFlagsFunc = extraLdapFlagsFuncImpl
	extraLdapActionsFlagsMapFunc = extraLdapActionsFlagsMapFuncImpl
	extraLdapFlagsHandlingFunc = extraLdapFlagsHandlingFuncImpl
}

func extraLdapActionsFlagsMapFuncImpl() map[string][]string {
	return map[string][]string{
		"create": {groupNamesFlagName},
		"update": {groupNamesFlagName},
	}
}

func (c *LdapCommand) extraLdapHelpFunc(helpMap map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary managed-groups create ldap [options] [args]",
			"",
			"  Create a ldap-type managed group. Example:",
			"",
			`    $ boundary managed-groups create ldap -group-names admin -description "Ldap managed group for ProdOps"`,
			"",
			"",
		})

	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary managed-groups update ldap [options] [args]",
			"",
			"  Update an ldap-type managed group given its ID. Example:",
			"",
			`    $ boundary managed-groups update ldap -id acctldap_1234567890 -name "devops" -description "Ldap managed group for DevOps"`,
			"",
			"",
		})
	}
	return helpStr + c.Flags().Help()
}

func extraLdapFlagsFuncImpl(c *LdapCommand, _ *base.FlagSets, f *base.FlagSet) {
	for _, name := range flagsLdapMap[c.Func] {
		switch name {
		case groupNamesFlagName:
			f.StringSliceVar(&base.StringSliceVar{
				Name:   groupNamesFlagName,
				Target: &c.flagGroupNames,
				Usage:  "The LDAP group names against which an LDAP account's associated groups (discovered during login) will be evaluated to determine membership (required). May be specified multiple times",
			})
		}
	}
}

func extraLdapFlagsHandlingFuncImpl(c *LdapCommand, _ *base.FlagSets, opts *[]managedgroups.Option) bool {
	switch {
	case len(c.flagGroupNames) == 0:
	case len(c.flagGroupNames) == 1 && c.flagGroupNames[0] == "null":
		c.UI.Error(fmt.Sprintf("There must be at least one %q", groupNamesFlagName))
		return false
	default:
		*opts = append(*opts, managedgroups.WithLdapManagedGroupGroupNames(c.flagGroupNames))
	}

	return true
}
