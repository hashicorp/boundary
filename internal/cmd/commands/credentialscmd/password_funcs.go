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
	extraPasswordFlagsFunc = extraPasswordFlagsFuncImpl
	extraPasswordActionsFlagsMapFunc = extraPasswordActionsFlagsMapFuncImpl
	extraPasswordFlagsHandlingFunc = extraPasswordFlagHandlingFuncImpl
}

type extraPasswordCmdVars struct {
	flagPassword string
}

func extraPasswordActionsFlagsMapFuncImpl() map[string][]string {
	flags := map[string][]string{
		"create": {
			passwordFlagName,
		},
	}
	flags["update"] = flags["create"]
	return flags
}

func extraPasswordFlagsFuncImpl(c *PasswordCommand, set *base.FlagSets, _ *base.FlagSet) {
	f := set.NewFlagSet("Password Credential Options")

	for _, name := range flagsPasswordMap[c.Func] {
		switch name {
		case passwordFlagName:
			f.StringVar(&base.StringVar{
				Name:   passwordFlagName,
				Target: &c.flagPassword,
				Usage:  "The password associated with the credential. This can be a file on disk (file://) from which the value will be read, or an env var (env://) from which the value will be read.",
			})
		}
	}
}

func extraPasswordFlagHandlingFuncImpl(c *PasswordCommand, _ *base.FlagSets, opts *[]credentials.Option) bool {
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
		*opts = append(*opts, credentials.WithPasswordCredentialPassword(password))
	}

	return true
}

func (c *PasswordCommand) extraPasswordHelpFunc(_ map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary credentials create password -credential-store-id [options] [args]",
			"",
			"  Create a password credential. Example:",
			"",
			`    $ boundary credentials create password -credential-store-id csvlt_1234567890 -password pass`,
			"",
			"",
		})

	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary credentials update password [options] [args]",
			"",
			"  Update a password credential given its ID. Example:",
			"",
			`    $ boundary credentials update password -id clvlt_1234567890 -name devops -description "For DevOps usage"`,
			"",
			"",
		})
	}
	return helpStr + c.Flags().Help()
}
