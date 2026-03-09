// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package clientagentcmd

import (
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*ClientAgentCommand)(nil)
	_ cli.CommandAutocomplete = (*ClientAgentCommand)(nil)
)

type ClientAgentCommand struct {
	*base.Command
}

func (c *ClientAgentCommand) Synopsis() string {
	return "Manages the Boundary client agent"
}

func (c *ClientAgentCommand) Help() string {
	helpText := `
Usage: boundary client-agent [sub command] [options]

  This command allows interacting with the Boundary client agent.

  Get the status of the agent:

      $ boundary client-agent status

  Pause and resume the agent:

      $ boundary client-agent pause
      $ boundary client-agent resume

  List active transparent sessions:

      $ boundary client-agent sessions

  For a full list of examples, please see the documentation.

`
	return strings.TrimSpace(helpText)
}

func (c *ClientAgentCommand) Flags() *base.FlagSets {
	return c.FlagSet(base.FlagSetNone)
}

func (c *ClientAgentCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictNothing
}

func (c *ClientAgentCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *ClientAgentCommand) Run(args []string) int {
	return cli.RunResultHelp
}

// clientAgentUrl constructs the full URL for a client agent request given a port and path.
func clientAgentUrl(port uint16, path string) string {
	return fmt.Sprintf("http://localhost:%d/%s", port, path)
}
