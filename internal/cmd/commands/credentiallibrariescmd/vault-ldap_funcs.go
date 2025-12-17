// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package credentiallibrariescmd

import (
	"github.com/hashicorp/boundary/api/credentiallibraries"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func init() {
	extraVaultLdapActionsFlagsMapFunc = extraVaultLdapActionsFlagsMapFuncImpl
	extraVaultLdapFlagsFunc = extraVaultLdapFlagsFuncImpl
	extraVaultLdapFlagsHandlingFunc = extraVaultLdapFlagHandlingFuncImpl
}

type extraVaultLdapCmdVars struct {
	flagPath string
}

func extraVaultLdapActionsFlagsMapFuncImpl() map[string][]string {
	flags := map[string][]string{
		"create": {
			pathFlagName,
		},
		"update": {
			pathFlagName,
		},
	}
	return flags
}

func extraVaultLdapFlagsFuncImpl(c *VaultLdapCommand, set *base.FlagSets, _ *base.FlagSet) {
	f := set.NewFlagSet("Vault Ldap Credential Library Options")

	for _, name := range flagsVaultLdapMap[c.Func] {
		switch name {
		case pathFlagName:
			f.StringVar(&base.StringVar{
				Name:   pathFlagName,
				Target: &c.flagPath,
				Usage:  "The path in vault to request credentials from.",
			})
		}
	}
}

func extraVaultLdapFlagHandlingFuncImpl(c *VaultLdapCommand, _ *base.FlagSets, opts *[]credentiallibraries.Option) bool {
	switch c.flagPath {
	case "":
	default:
		*opts = append(*opts, credentiallibraries.WithVaultLdapCredentialLibraryPath(c.flagPath))
	}
	return true
}

func (c *VaultLdapCommand) extraVaultLdapHelpFunc(_ map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary credential-libraries create vault-ldap -credential-store-id [options] [args]",
			"",
			"  Create a vault-ldap-type credential library. Example:",
			"",
			`    $ boundary credential-libraries create vault-ldap -credential-store-id csvlt_1234567890 -vault-path "/ldap/static-cred/einstein"`,
			"",
			"",
		})

	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary credential-libraries update vault-ldap [options] [args]",
			"",
			"  Update a vault-ldap-type credential library given its ID. Example:",
			"",
			`    $ boundary credential-libraries update vault-ldap -id clvllt_1234567890 -name devops -description "For DevOps usage"`,
			"",
			"",
		})
	}
	return helpStr + c.Flags().Help()
}
