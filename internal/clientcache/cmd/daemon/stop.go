// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
	"strings"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/posener/complete"
)

type StopCommand struct {
	*base.Command
}

func (c *StopCommand) Synopsis() string {
	return "Stop a Boundary daemon"
}

func (c *StopCommand) Help() string {
	helpText := `
Usage: boundary daemon stop

  Stop a daemon:

      $ boundary daemon stop

  For a full list of examples, please see the documentation.

` + c.Flags().Help()
	return strings.TrimSpace(helpText)
}

func (c *StopCommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient)
	return set
}

func (c *StopCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictNothing
}

func (c *StopCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *StopCommand) Run(args []string) int {
	ctx, cancel := context.WithCancel(c.Context)
	c.Context = ctx
	c.ContextCancel = cancel

	f := c.Flags()
	if err := f.Parse(args); err != nil {
		c.PrintCliError(err)
		return base.CommandUserError
	}
	if err := c.stop(c.Context); err != nil {
		if errors.Match(errors.T(errors.NotFound), err) {
			c.PrintCliError(errDaemonNotRunning)
		} else {
			c.PrintCliError(err)
		}
		return base.CommandUserError
	}

	return base.CommandSuccess
}
