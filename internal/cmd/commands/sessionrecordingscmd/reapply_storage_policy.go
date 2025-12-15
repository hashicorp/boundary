// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package sessionrecordingscmd

import (
	"errors"
	"fmt"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/sessionrecordings"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/mitchellh/cli"
	"github.com/mitchellh/go-wordwrap"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*ReApplyStoragePolicyCommand)(nil)
	_ cli.CommandAutocomplete = (*ReApplyStoragePolicyCommand)(nil)
)

type ReApplyStoragePolicyCommand struct {
	*base.Command
}

func (c *ReApplyStoragePolicyCommand) Synopsis() string {
	return wordwrap.WrapString("Reapply storage policy to a session recording", base.TermWidth)
}

func (c *ReApplyStoragePolicyCommand) Help() string {
	return base.WrapForHelpText([]string{
		"Usage: boundary session-recordings reapply-storage-policy [args]",
		"",
		"  Reapply a storage policy to a session recording resource. Example:",
		"",
		`    $ boundary session-recordings reapply-storage-policy -id sr_0123456789`,
		"",
		"",
	}) + c.Flags().Help()
}

func (c *ReApplyStoragePolicyCommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)
	f := set.NewFlagSet("Command Options")
	f.StringVar(&base.StringVar{
		Name:   "id",
		Target: &c.FlagId,
		Usage:  "The id of the session recording resource to reapply.",
	})
	return set
}

func (c *ReApplyStoragePolicyCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictAnything
}

func (c *ReApplyStoragePolicyCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *ReApplyStoragePolicyCommand) Run(args []string) int {
	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.PrintCliError(err)
		return base.CommandUserError
	}

	switch {
	case c.FlagId == "":
		c.PrintCliError(errors.New("ID must be provided via -id"))
		return base.CommandUserError
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

	sClient := sessionrecordings.NewClient(client)
	result, err := sClient.ReApplyStoragePolicy(c.Context, c.FlagId)
	if err != nil {
		if apiErr := api.AsServerError(err); apiErr != nil {
			c.PrintApiError(apiErr, "Error from controller when reapplying storage policy to session recording")
			return base.CommandApiError
		}
		c.PrintCliError(fmt.Errorf("Reappling storage policy error: %w", err))
		return base.CommandCliError
	}
	resp := result.GetResponse()
	item := result.GetItem()

	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(printItemTable(item, resp))
	case "json":
		if ok := c.PrintJsonItem(resp); !ok {
			return base.CommandCliError
		}
	}

	return base.CommandSuccess
}
