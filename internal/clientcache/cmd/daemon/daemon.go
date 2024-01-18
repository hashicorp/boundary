// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"strings"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*StartCommand)(nil)
	_ cli.CommandAutocomplete = (*StartCommand)(nil)
)

type DaemonCommand struct {
	*base.Command
}

func (c *DaemonCommand) Synopsis() string {
	return "Manages the client side Boundary cache daemon"
}

func (c *DaemonCommand) Help() string {
	helpText := `
Usage: boundary daemon [sub command] [options]

  This command allows interacting with the Boundary daemon.

  Start a daemon:

      $ boundary daemon start

  For a full list of examples, please see the documentation.

`
	return strings.TrimSpace(helpText)
}

func (c *DaemonCommand) Flags() *base.FlagSets {
	return c.FlagSet(base.FlagSetNone)
}

func (c *DaemonCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictNothing
}

func (c *DaemonCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *DaemonCommand) Run(args []string) int {
	return cli.RunResultHelp
}
