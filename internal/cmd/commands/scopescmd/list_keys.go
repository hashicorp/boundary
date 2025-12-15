// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package scopescmd

import (
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/mitchellh/cli"
	"github.com/mitchellh/go-wordwrap"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*ListKeysCommand)(nil)
	_ cli.CommandAutocomplete = (*ListKeysCommand)(nil)
)

type ListKeysCommand struct {
	*base.Command
}

func (c *ListKeysCommand) Synopsis() string {
	return wordwrap.WrapString("List keys within a scope", base.TermWidth)
}

func (c *ListKeysCommand) Help() string {
	return base.WrapForHelpText([]string{
		"Usage: boundary scopes list-keys [args]",
		"",
		"  List keys within a scope. Example:",
		"",
		`    $ boundary scopes list-keys -scope-id global`,
		"",
		"",
	}) + c.Flags().Help()
}

func (c *ListKeysCommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)
	f := set.NewFlagSet("Command Options")

	f.StringVar(&base.StringVar{
		Name:   "scope-id",
		Target: &c.FlagScopeId,
		Usage:  "The id of the scope in which to list the keys",
	})

	return set
}

func (c *ListKeysCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictAnything
}

func (c *ListKeysCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *ListKeysCommand) printListTable(items []*scopes.Key) string {
	if len(items) == 0 {
		return "No keys found"
	}
	var output []string
	output = []string{
		"",
		"Key information:",
	}
	for i, item := range items {
		if i > 0 {
			output = append(output, "")
		}
		if true {
			output = append(output,
				fmt.Sprintf("  ID:          %s", item.Id),
				fmt.Sprintf("    Scope ID:  %s", item.Scope.Id),
			)
		}
		if item.Type != "" {
			output = append(output,
				fmt.Sprintf("    Type:      %s", item.Type),
			)
		}
		if item.Purpose != "" {
			output = append(output,
				fmt.Sprintf("    Purpose:   %s", item.Purpose),
			)
		}
		output = append(output, "    Key Versions:")
		for _, keyVersion := range item.Versions {
			if true {
				output = append(output,
					fmt.Sprintf("      Version:   %d", keyVersion.Version),
				)
			}
			if keyVersion.Id != "" {
				output = append(output,
					fmt.Sprintf("        ID:      %s", keyVersion.Id),
				)
			}
			if !keyVersion.CreatedTime.IsZero() {
				output = append(output,
					fmt.Sprintf("        Created: %s", keyVersion.CreatedTime.Local().Format(time.RFC1123)),
				)
			}
		}
	}

	return base.WrapForHelpText(output)
}

func (c *ListKeysCommand) Run(args []string) int {
	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.PrintCliError(err)
		return base.CommandUserError
	}

	switch {
	case c.FlagScopeId == "":
		c.PrintCliError(errors.New("Scope ID must be provided via -scope-id"))
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

	sClient := scopes.NewClient(client)
	result, err := sClient.ListKeys(c.Context, c.FlagScopeId)
	if err != nil {
		if apiErr := api.AsServerError(err); apiErr != nil {
			c.PrintApiError(apiErr, "Error from controller when listing scope keys")
			return base.CommandApiError
		}
		c.PrintCliError(fmt.Errorf("Error trying to list scope keys: %w", err))
		return base.CommandCliError
	}

	switch base.Format(c.UI) {
	case "json":
		if ok := c.PrintJsonItems(result.GetResponse()); !ok {
			return base.CommandCliError
		}

	default:
		c.UI.Output(c.printListTable(result.GetItems()))
	}

	return base.CommandSuccess
}
