// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/mitchellh/cli"
)

var _ cli.Command = (*Command)(nil)

type Command struct {
	*base.Command
}

func (c *Command) Synopsis() string {
	return "Manage the local client's configuration"
}

func (c *Command) Help() string {
	return base.WrapForHelpText([]string{
		"Usage: boundary config <subcommand> [options] [args]",
		"",
		"  This command groups subcommands for operators interacting with Boundary's config files. Here are a few examples of config commands:",
		"",
		"    Encrypt sensitive values in a config file:",
		"",
		"      $ boundary config encrypt config.hcl",
		"",
		"    Decrypt sensitive values in a config file:",
		"",
		"      $ boundary config decrypt config.hcl",
		"",
		"    Read a stored token out:",
		"",
		"      $ boundary config get-token",
		"",
		"  Please see the individual subcommand help for detailed usage information.",
	})
}

func (c *Command) Run(args []string) int {
	return cli.RunResultHelp
}
