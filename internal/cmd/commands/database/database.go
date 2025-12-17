// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package database

import (
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*Command)(nil)
	_ cli.CommandAutocomplete = (*Command)(nil)
)

type Command struct {
	*base.Command
}

func (c *Command) Synopsis() string {
	return "Manage Boundary's database"
}

func (c *Command) Help() string {
	return base.WrapForHelpText([]string{
		"Usage: boundary database [sub command] [options] [args]",
		"",
		"  This command allows operations on Boundary's database. Example:",
		"",
		"    Initialize the database:",
		"",
		`      $ boundary database init`,
		"",
		"  Please see the database subcommand help for detailed usage information.",
	})
}

func (c *Command) Flags() *base.FlagSets {
	return nil
}

func (c *Command) AutocompleteArgs() complete.Predictor {
	return complete.PredictAnything
}

func (c *Command) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *Command) Run(args []string) int {
	return cli.RunResultHelp
}
