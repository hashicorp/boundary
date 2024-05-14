// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package ferry

import (
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*FerryCommand)(nil)
	_ cli.CommandAutocomplete = (*FerryCommand)(nil)
)

type FerryCommand struct {
	*base.Command
}

func (c *FerryCommand) Synopsis() string {
	return "Manages the Boundary ferry daemon"
}

func (c *FerryCommand) Help() string {
	helpText := `
Usage: boundary ferry [sub command] [options]

  This command allows interacting with the Boundary ferry daemon.

  Get the status of the daemon:

      $ boundary ferry status

  Pause and resume the daemon:

      $ boundary ferry pause
      $ boundary ferry resume

  List active transparent sessions:

      $ boundary ferry sessions

  For a full list of examples, please see the documentation.

`
	return strings.TrimSpace(helpText)
}

func (c *FerryCommand) Flags() *base.FlagSets {
	return c.FlagSet(base.FlagSetNone)
}

func (c *FerryCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictNothing
}

func (c *FerryCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *FerryCommand) Run(args []string) int {
	return cli.RunResultHelp
}

// ferryUrl constructs the full URL for a ferry request given a port and path.
func ferryUrl(port uint, path string) string {
	return fmt.Sprintf("http://127.0.0.1:%d/%s", port, path)
}
