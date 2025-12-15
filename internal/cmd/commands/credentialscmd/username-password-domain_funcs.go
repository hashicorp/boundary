// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package credentialscmd

import (
	"errors"
	"fmt"

	"github.com/hashicorp/boundary/api/credentials"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
)

func init() {
	extraUsernamePasswordDomainFlagsFunc = extraUsernamePasswordDomainFlagsFuncImpl
	extraUsernamePasswordDomainActionsFlagsMapFunc = extraUsernamePasswordDomainActionsFlagsMapFuncImpl
	extraUsernamePasswordDomainFlagsHandlingFunc = extraUsernamePasswordDomainFlagHandlingFuncImpl
}

type extraUsernamePasswordDomainCmdVars struct {
	flagUsername string
	flagPassword string
	flagDomain   string
}

func extraUsernamePasswordDomainActionsFlagsMapFuncImpl() map[string][]string {
	flags := map[string][]string{
		"create": {
			usernameFlagName,
			passwordFlagName,
			domainFlagName,
		},
	}
	flags["update"] = flags["create"]
	return flags
}

func extraUsernamePasswordDomainFlagsFuncImpl(c *UsernamePasswordDomainCommand, set *base.FlagSets, _ *base.FlagSet) {
	f := set.NewFlagSet("Username/Password/Domain Credential Options")

	for _, name := range flagsUsernamePasswordDomainMap[c.Func] {
		switch name {
		case usernameFlagName:
			f.StringVar(&base.StringVar{
				Name:   usernameFlagName,
				Target: &c.flagUsername,
				Usage:  "The username associated with the credential. This can be a username, or a username with a domain in the format of username@domain or domain\\username",
			})
		case passwordFlagName:
			f.StringVar(&base.StringVar{
				Name:   passwordFlagName,
				Target: &c.flagPassword,
				Usage:  "The password associated with the credential. This can be a file on disk (file://) from which the value will be read, or an env var (env://) from which the value will be read.",
			})
		case domainFlagName:
			f.StringVar(&base.StringVar{
				Name:   domainFlagName,
				Target: &c.flagDomain,
				Usage:  "The domain associated with the credential. If this is not provided, it will be derived from the username field if the username is in the format of username@domain or domain\\username",
			})
		}
	}
}

func extraUsernamePasswordDomainFlagHandlingFuncImpl(c *UsernamePasswordDomainCommand, _ *base.FlagSets, opts *[]credentials.Option) bool {
	username, domain, err := credentials.ParseUsernameDomain(c.flagUsername, c.flagDomain)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error parsing username and domain: %v", err))
		return false
	}

	switch username {
	case "":
	default:
		*opts = append(*opts, credentials.WithUsernamePasswordDomainCredentialUsername(username))
	}

	switch domain {
	case "":
	default:
		*opts = append(*opts, credentials.WithUsernamePasswordDomainCredentialDomain(domain))
	}

	switch c.flagPassword {
	case "":
	default:
		password, err := parseutil.MustParsePath(c.flagPassword)
		switch {
		case err == nil:
		case errors.Is(err, parseutil.ErrNotParsed):
			c.UI.Error("Password flag must be used with env:// or file:// syntax")
			return false
		default:
			c.UI.Error(fmt.Sprintf("Error parsing password flag: %v", err))
			return false
		}
		*opts = append(*opts, credentials.WithUsernamePasswordDomainCredentialPassword(password))
	}

	return true
}

func (c *UsernamePasswordDomainCommand) extraUsernamePasswordDomainHelpFunc(_ map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary credentials create username-password-domain -credential-store-id [options] [args]",
			"",
			"  Create a username password domain credential. Example:",
			"",
			`    $ boundary credentials create username-password-domain -credential-store-id csvlt_1234567890 -username user -password env://PASSWORD -domain domain`,
			"",
			"",
		})

	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary credentials update username-password-domain [options] [args]",
			"",
			"  Update a username password domain credential given its ID. Example:",
			"",
			`    $ boundary credentials update username-password-domain -id clvlt_1234567890 -name devops -description "For DevOps usage"`,
			"",
			"",
		})
	}
	return helpStr + c.Flags().Help()
}
