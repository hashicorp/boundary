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
	_ cli.Command             = (*DestroyKeyVersionCommand)(nil)
	_ cli.CommandAutocomplete = (*DestroyKeyVersionCommand)(nil)
)

type DestroyKeyVersionCommand struct {
	*base.Command
	FlagKeyVersionId string
}

func (c *DestroyKeyVersionCommand) Synopsis() string {
	return wordwrap.WrapString("Destroy a key version within a scope", base.TermWidth)
}

func (c *DestroyKeyVersionCommand) Help() string {
	return base.WrapForHelpText([]string{
		"Usage: boundary scopes destroy-key-version [args]",
		"",
		"  Destroys a key version in the scope. The key version must not be the currently active key version.",
		"  This may start an asynchronous job to re-encrypt existing data encrypted with the key version.",
		"  Use `boundary scopes list-key-version-destruction-jobs` to monitor the progress of this job. Example:",
		"",
		`    $ boundary scopes destroy-key-version -scope-id global -key-version-id krkv_123456789`,
		"",
		"",
	}) + c.Flags().Help()
}

func (c *DestroyKeyVersionCommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)
	f := set.NewFlagSet("Command Options")

	f.StringVar(&base.StringVar{
		Name:   "scope-id",
		Target: &c.FlagScopeId,
		Usage:  "The id of the scope in which the key version exists",
	})

	f.StringVar(&base.StringVar{
		Name:   "key-version-id",
		Target: &c.FlagKeyVersionId,
		Usage:  "The id of the key version which should be destroyed",
	})
	return set
}

func (c *DestroyKeyVersionCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictAnything
}

func (c *DestroyKeyVersionCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *DestroyKeyVersionCommand) Run(args []string) int {
	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.PrintCliError(err)
		return base.CommandUserError
	}

	switch {
	case c.FlagScopeId == "":
		c.PrintCliError(errors.New("Scope ID must be provided via -scope-id"))
		return base.CommandUserError
	case c.FlagKeyVersionId == "":
		c.PrintCliError(errors.New("Key Version ID must be provided via -key-version-id"))
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
	result, err := sClient.DestroyKeyVersion(c.Context, c.FlagScopeId, c.FlagKeyVersionId)
	if err != nil {
		if apiErr := api.AsServerError(err); apiErr != nil {
			c.PrintApiError(apiErr, "Error from controller when destroying key version")
			return base.CommandApiError
		}
		c.PrintCliError(fmt.Errorf("Error trying to destroy key version: %w", err))
		return base.CommandCliError
	}

	switch base.Format(c.UI) {
	case "json":
		if ok := c.PrintJsonItem(result.GetResponse()); !ok {
			return base.CommandCliError
		}
	default:
		switch result.State {
		case "completed":
			c.UI.Output("The key version was successfully destroyed.")
		case "pending":
			c.UI.Output("A key version destruction job has been created, which will re-encrypt existing data in the background. Use `boundary scopes list-key-version-destruction-jobs` to monitor this job. Once it has completed the key version will have been destroyed.")
		default:
			c.PrintCliError(fmt.Errorf("unexpected state: %q", result.State))
			return base.CommandApiError
		}
	}

	return base.CommandSuccess
}
