// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package docscmd

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/api/help"
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

func (c *Command) AutocompleteArgs() complete.Predictor {
	return complete.PredictAnything
}

func (c *Command) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *Command) Synopsis() string {
	return "Request help to use Boundary"
}

func (c *Command) Help() string {
	return base.WrapForHelpText([]string{
		"Usage: boundary docs [options] <query>",
		"",
		"  This command can help questions about how to use Boundary. Example:",
		"",
		`      $ boundary docs "How do I create a target?"`,
	})
}

func (c *Command) Flags() *base.FlagSets {
	return c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)
}

func (c *Command) Run(args []string) int {
	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.PrintCliError(err)
		return base.CommandUserError
	}

	if len(args) != 1 {
		c.PrintCliError(fmt.Errorf("Usage: boundary docs [options] <query>"))
		return base.CommandCliError
	}

	client, err := c.Client()
	if c.WrapperCleanupFunc != nil {
		defer func() {
			if err := c.WrapperCleanupFunc(); err != nil {
				c.PrintCliError(fmt.Errorf("Error cleaning kms wrapper: %w", err))
			}
		}()
	}
	if err != nil {
		c.PrintCliError(fmt.Errorf("Error creating API client: %w", err))
		return base.CommandCliError
	}
	helpClient := help.NewClient(client)

	resp, err := helpClient.Help(context.Background(), args[0])
	if err != nil {
		c.PrintCliError(err)
		return base.CommandApiError
	}

	c.UI.Output(resp.Answer)

	return base.CommandSuccess
}
