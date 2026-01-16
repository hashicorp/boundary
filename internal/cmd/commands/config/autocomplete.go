// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/mitchellh/cli"
)

var _ cli.Command = (*Command)(nil)

type AutocompleteCommand struct {
	*base.Command

	Func string
}

func (c *AutocompleteCommand) Synopsis() string {
	verb := "Install"
	switch c.Func {
	case "uninstall":
		verb = "Uninstall"
	case "base":
		verb = "Install or uninstall"
	}

	return fmt.Sprintf("%s autocompletion for Boundary's CLI", verb)
}

func (c *AutocompleteCommand) Help() string {
	verb := "installs"
	switch c.Func {
	case "uninstall":
		verb = "uninstalls"
	case "base":
		verb = "installs or uninstalls"
	}

	subcmd := ""
	switch c.Func {
	case "uninstall":
		subcmd = " uninstall"
	case "install":
		subcmd = " install"
	}
	return base.WrapForHelpText([]string{
		fmt.Sprintf("Usage: boundary config autocomplete%s [options] [args]", subcmd),
		"",
		fmt.Sprintf("  This command %s autocompletion support for Boundary's CLI", verb),
	})
}

func (c *AutocompleteCommand) Run(args []string) int {
	if len(args) > 0 {
		return cli.RunResultHelp
	}
	return base.CommandSuccess
}
