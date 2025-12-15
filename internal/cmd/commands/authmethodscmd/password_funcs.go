// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package authmethodscmd

import (
	"fmt"
	"strconv"

	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func init() {
	extraPasswordActionsFlagsMapFunc = extraPasswordActionsFlagsMapFuncImpl
	extraPasswordFlagsFunc = extraPasswordFlagsFuncImpl
	extraPasswordFlagsHandlingFunc = extraPasswordFlagHandlingFuncImpl
}

type extraPasswordCmdVars struct {
	flagMinLoginNameLength string
	flagMinPasswordLength  string
}

func extraPasswordActionsFlagsMapFuncImpl() map[string][]string {
	return map[string][]string{
		"create": {"min-login-name-length", "min-password-length"},
		"update": {"min-login-name-length", "min-password-length"},
	}
}

func (c *PasswordCommand) extraPasswordHelpFunc(helpMap map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary auth-methods create password [options] [args]",
			"",
			"  Create a password-type auth method. Example:",
			"",
			`    $ boundary auth-methods create password -name prodops -description "Password auth-method for ProdOps"`,
			"",
			"",
		})

	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary auth-methods update password [options] [args]",
			"",
			"  Update a password-type auth method given its ID. Example:",
			"",
			`    $ boundary auth-methods update password -id ampw_1234567890 -name "devops" -description "Password auth-method for DevOps"`,
			"",
			"",
		})
	}
	return helpStr + c.Flags().Help()
}

func extraPasswordFlagsFuncImpl(c *PasswordCommand, set *base.FlagSets, _ *base.FlagSet) {
	f := set.NewFlagSet("Password Auth Method Options")

	for _, name := range flagsPasswordMap[c.Func] {
		switch name {
		case "min-login-name-length":
			f.StringVar(&base.StringVar{
				Name:   "min-login-name-length",
				Target: &c.flagMinLoginNameLength,
				Usage:  "The minimum length of login names",
			})
		case "min-password-length":
			f.StringVar(&base.StringVar{
				Name:   "min-password-length",
				Target: &c.flagMinPasswordLength,
				Usage:  "The minimum length of passwords",
			})
		}
	}
}

func extraPasswordFlagHandlingFuncImpl(c *PasswordCommand, _ *base.FlagSets, opts *[]authmethods.Option) bool {
	var attributes map[string]any
	addAttribute := func(name string, value any) {
		if attributes == nil {
			attributes = make(map[string]any)
		}
		attributes[name] = value
	}
	switch c.flagMinLoginNameLength {
	case "":
	case "null":
		addAttribute("min_login_name_length", nil)
	default:
		length, err := strconv.ParseUint(c.flagMinLoginNameLength, 10, 32)
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error parsing %q: %s", c.flagMinLoginNameLength, err))
			return false
		}
		addAttribute("min_login_name_length", uint32(length))
	}

	switch c.flagMinPasswordLength {
	case "":
	case "null":
		addAttribute("min_password_length", nil)
	default:
		length, err := strconv.ParseUint(c.flagMinPasswordLength, 10, 32)
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error parsing %q: %s", c.flagMinPasswordLength, err))
			return false
		}
		addAttribute("min_password_length", uint32(length))
	}

	if attributes != nil {
		*opts = append(*opts, authmethods.WithAttributes(attributes))
	}

	return true
}
