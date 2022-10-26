package scopescmd

import (
	"errors"
	"fmt"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/mitchellh/cli"
	"github.com/mitchellh/go-wordwrap"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*RotateKeysCommand)(nil)
	_ cli.CommandAutocomplete = (*RotateKeysCommand)(nil)
)

type RotateKeysCommand struct {
	*base.Command
}

func (c *RotateKeysCommand) Synopsis() string {
	return wordwrap.WrapString("Rotate the keys within a scope", base.TermWidth)
}

func (c *RotateKeysCommand) Help() string {
	return base.WrapForHelpText([]string{
		"Usage: boundary scopes rotate-keys [args]",
		"",
		"  Deactivates a given scope's current KEK and DEKs and activates a new set of keys for the scope. Example:",
		"",
		`    $ boundary scopes rotate-keys -scope-id global`,
		"",
		"",
	}) + c.Flags().Help()
}

func (c *RotateKeysCommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)
	f := set.NewFlagSet("Command Options")

	f.StringVar(&base.StringVar{
		Name:   "scope-id",
		Target: &c.FlagScopeId,
		Usage:  "The id of the scope in which to rotate keys",
	})

	f.BoolVar((&base.BoolVar{
		Name:   "rewrap",
		Target: &c.FlagRewrap,
		Usage:  "Whether or not to re-encrypt DEKs with the new KEK",
	}))

	return set
}

func (c *RotateKeysCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictAnything
}

func (c *RotateKeysCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *RotateKeysCommand) Run(args []string) int {
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
	result, err := sClient.RotateKeys(c.Context, c.FlagScopeId, c.FlagRewrap)
	if err != nil {
		if apiErr := api.AsServerError(err); apiErr != nil {
			c.PrintApiError(apiErr, "Error from controller when rotating scope keys")
			return base.CommandApiError
		}
		c.PrintCliError(fmt.Errorf("Error trying to rotate scope keys: %w", err))
		return base.CommandCliError
	}

	switch base.Format(c.UI) {
	case "json":
		if ok := c.PrintJsonItem(result.GetResponse()); !ok {
			return base.CommandCliError
		}

	default:
		c.UI.Output("The rotate operation completed successfully.")
	}

	return base.CommandSuccess
}
