// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package accountscmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/boundary/api/accounts"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/go-secure-stdlib/password"
	"github.com/hashicorp/go-secure-stdlib/strutil"
)

func init() {
	extraPasswordActionsFlagsMapFunc = extraPasswordActionsFlagsMapFuncImpl
	extraPasswordFlagsFunc = extraPasswordFlagsFuncImpl
	extraPasswordFlagsHandlingFunc = extraPasswordFlagsHandlingFuncImpl
}

func extraPasswordActionsFlagsMapFuncImpl() map[string][]string {
	return map[string][]string{
		"create": {"login-name", "password"},
		"update": {"login-name"},
	}
}

type extraPasswordCmdVars struct {
	flagLoginName string
	flagPassword  string
}

func (c *PasswordCommand) extraPasswordHelpFunc(helpMap map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary accounts create password [options] [args]",
			"",
			"  Create a password-type account. Example:",
			"",
			`    $ boundary accounts create password -login-name prodops -description "Password account for ProdOps"`,
			"",
			"",
		})

	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary accounts update password [options] [args]",
			"",
			"  Update a password-type account given its ID. Example:",
			"",
			`    $ boundary accounts update password -id acctpw_1234567890 -name "devops" -description "Password account for DevOps"`,
			"",
			"",
		})
	}
	return helpStr + c.Flags().Help()
}

func extraPasswordFlagsFuncImpl(c *PasswordCommand, set *base.FlagSets, _ *base.FlagSet) {
	f := set.NewFlagSet("Password Account Options")

	for _, name := range flagsPasswordMap[c.Func] {
		switch name {
		case "login-name":
			f.StringVar(&base.StringVar{
				Name:   "login-name",
				Target: &c.flagLoginName,
				Usage:  "The login name for the account",
			})
		case "password":
			f.StringVar(&base.StringVar{
				Name:   "password",
				Target: &c.flagPassword,
				Usage:  "The password for the account. If blank, the command will prompt for the password to be entered interactively in a non-echoing way. Otherwise, this can refer to a file on disk (file://) from which a password will be read or an env var (env://) from which the password will be read.",
			})
		}
	}
}

func extraPasswordFlagsHandlingFuncImpl(c *PasswordCommand, _ *base.FlagSets, opts *[]accounts.Option) bool {
	if c.Func == "create" && c.flagLoginName == "" {
		c.UI.Error("Login Name must be passed in via -login-name")
		return false
	}

	switch c.flagLoginName {
	case "":
	case "null":
		*opts = append(*opts, accounts.DefaultPasswordAccountLoginName())
	default:
		*opts = append(*opts, accounts.WithPasswordAccountLoginName(c.flagLoginName))
	}

	if strutil.StrListContains(flagsPasswordMap[c.Func], "password") {
		switch c.flagPassword {
		case "":
			fmt.Print("Please enter the password (it will be hidden): ")
			value, err := password.Read(os.Stdin)
			fmt.Print("\n")
			if err != nil {
				c.UI.Error(fmt.Sprintf("An error occurred attempting to read the password. The raw error message is shown below but usually this is because you attempted to pipe a value into the command or you are executing outside of a terminal (TTY). The raw error was:\n\n%s", err.Error()))
				return false
			}
			fmt.Print("Please enter it one more time for confirmation: ")
			confirmation, err := password.Read(os.Stdin)
			fmt.Print("\n")
			if err != nil {
				c.UI.Error(fmt.Sprintf("An error occurred attempting to read the password. The raw error message is shown below but usually this is because you attempted to pipe a value into the command or you are executing outside of a terminal (TTY). The raw error was:\n\n%s", err.Error()))
				return false
			}
			if strings.TrimSpace(value) != strings.TrimSpace(confirmation) {
				c.UI.Error("Entered password and confirmation value did not match.")
				return false
			}
			*opts = append(*opts, accounts.WithPasswordAccountPassword(strings.TrimSpace(value)))

		default:
			password, err := parseutil.MustParsePath(c.flagPassword)
			switch {
			case err == nil:
			case errors.Is(err, parseutil.ErrNotParsed):
				c.UI.Error("Password flag must be used with env:// or file:// syntax or left empty for an interactive prompt")
				return false
			default:
				c.UI.Error(fmt.Sprintf("Error parsing password flag: %v", err))
				return false
			}
			*opts = append(*opts, accounts.WithPasswordAccountPassword(password))
		}
	}

	return true
}
