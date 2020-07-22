package scopes

import (
	"fmt"
	"strings"

	"github.com/hashicorp/watchtower/api"
	"github.com/hashicorp/watchtower/api/scopes"
	"github.com/hashicorp/watchtower/internal/cmd/base"
	"github.com/kr/pretty"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var _ cli.Command = (*ReadScopeCommand)(nil)
var _ cli.CommandAutocomplete = (*ReadScopeCommand)(nil)

type ReadScopeCommand struct {
	*base.Command

	flagId string
}

func (c *ReadScopeCommand) Synopsis() string {
	return "Reads a scope's data"
}

func (c *ReadScopeCommand) Help() string {
	helpText := `
Usage: watchtower scopes read 

  Returns information about a scope specified by the ID. The request will take place within the scope of the caller's authentication token.

  Example: 

      $ watchtower scopes read -id=<scope_id>

` + c.Flags().Help()

	return strings.TrimSpace(helpText)
}

func (c *ReadScopeCommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)

	f := set.NewFlagSet("Command Options")

	f.StringVar(&base.StringVar{
		Name:       "id",
		Target:     &c.flagId,
		Completion: complete.PredictNothing,
		Usage:      "The ID of the scope to read",
	})

	return set
}

func (c *ReadScopeCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictAnything
}

func (c *ReadScopeCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *ReadScopeCommand) Run(args []string) int {
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

	id := c.flagId
	if id == "" {
		id = client.ScopeId()
	}
	scp := &scopes.Scope{
		Client: client,
	}

	var apiErr *api.Error
	scp, apiErr, err = scp.ReadScope(c.Context, id)

	switch {
	case err != nil:
		c.UI.Error(fmt.Errorf("error reading project: %w", err).Error())
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
