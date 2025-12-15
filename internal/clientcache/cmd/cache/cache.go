// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package cache

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

type CacheCommand struct {
	*base.Command
}

func (c *CacheCommand) Synopsis() string {
	return "Manages the client side Boundary cache"
}

func (c *CacheCommand) Help() string {
	helpText := `
Usage: boundary cache [sub command] [options]

  This command allows interacting with the Boundary cache.

  Start a cache:

      $ boundary cache start

  For a full list of examples, please see the documentation.

`
	return strings.TrimSpace(helpText)
}

func (c *CacheCommand) Flags() *base.FlagSets {
	return c.FlagSet(base.FlagSetNone)
}

func (c *CacheCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictNothing
}

func (c *CacheCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *CacheCommand) Run(args []string) int {
	if len(args) >= 2 && args[1] == "daemon" {
		c.UI.Warn("The `boundary daemon` command is deprecated, use `boundary cache` instead")
	}
	return cli.RunResultHelp
}
