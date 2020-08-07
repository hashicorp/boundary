package scopes

import (
	"fmt"
	"strings"

	"github.com/hashicorp/watchtower/api/scopes"
	"github.com/hashicorp/watchtower/internal/cmd/base"
	"github.com/kr/pretty"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var _ cli.Command = (*CreateScopeCommand)(nil)
var _ cli.CommandAutocomplete = (*CreateScopeCommand)(nil)

type CreateScopeCommand struct {
	*base.Command

	flagName        string
	flagDescription string
}

func (c *CreateScopeCommand) Synopsis() string {
	return "Creates a scope within a parent scope"
}

func (c *CreateScopeCommand) Help() string {
	helpText := `
Usage: watchtower scopes create

  Creates a new scope within the scope specified by the ID from the
  "scope" parameter or the associated environment variable.

  Example: 

      $ watchtower scopes create -scope=<scope_id> -name=<name>

` + c.Flags().Help()

	return strings.TrimSpace(helpText)
}

func (c *CreateScopeCommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)

	f := set.NewFlagSet("Command Options")

	f.StringVar(&base.StringVar{
		Name:       "name",
		Target:     &c.flagName,
		Completion: complete.PredictAnything,
		Usage:      "An optional name assigned to the project for display purposes",
	})

	f.StringVar(&base.StringVar{
		Name:       "description",
		Target:     &c.flagDescription,
		Completion: complete.PredictNothing,
		Usage:      "An optional description assigned to the project for display purposes",
	})

	return set
}

func (c *CreateScopeCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictAnything
}

func (c *CreateScopeCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *CreateScopeCommand) Run(args []string) int {
	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	client, err := c.Client()
	if err != nil {
		c.UI.Error(err.Error())
		return 2
	}

	scp, apiErr, err := scopes.NewScopeClient(client).Create(c.Context,
		scopes.WithName(c.flagName),
		scopes.WithDescription(c.flagDescription))

	switch {
	case err != nil:
		c.UI.Error(fmt.Errorf("error creating project: %w", err).Error())
		return 2
	case apiErr != nil:
		c.UI.Error(pretty.Sprint(apiErr))
		return 2
	}

	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(printScope(scp))
	}

	return 0
}
