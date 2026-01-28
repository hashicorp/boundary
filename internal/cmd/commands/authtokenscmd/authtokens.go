// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package authtokenscmd

import "github.com/hashicorp/boundary/internal/cmd/base"

func (c *Command) extraHelpFunc(helpMap map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "":
		return base.WrapForHelpText([]string{
			"Usage: boundary auth-tokens [sub command] [options] [args]",
			"",
			"  This command allows operations on Boundary auth token resources. Example:",
			"",
			"    List all auth tokens:",
			"",
			`      $ boundary auth-tokens list -recursive `,
			"",
			"  Please see the auth-tokens subcommand help for detailed usage information.",
			"  Note: To create an auth token, see the authenticate subcommand.",
		})

	default:
		helpStr = helpMap["base"]()
	}
	return helpStr
}
