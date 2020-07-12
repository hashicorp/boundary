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

var _ cli.Command = (*ReadProjectCommand)(nil)
var _ cli.CommandAutocomplete = (*ReadProjectCommand)(nil)

type ReadProjectCommand struct {
	*base.Command

	flagId string
}

func (c *ReadProjectCommand) Synopsis() string {
	return "Reads a project's data"
}

func (c *ReadProjectCommand) Help() string {
	helpText := `
Usage: watchtower projects read 

  Returns information about a project specified by the ID. It is an error if
  the project is not within the org specified via the "org-id"
  parameter or the associated environment variable.

  Example: 

      $ watchtower projects read -org=<org_id> -id=<project_id>

` + c.Flags().Help()

	return strings.TrimSpace(helpText)
}

func (c *ReadProjectCommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)

	f := set.NewFlagSet("Command Options")

	f.StringVar(&base.StringVar{
		Name:       "id",
		Target:     &c.flagId,
		Completion: complete.PredictNothing,
		Usage:      "The ID of the project to read",
	})

	return set
}

func (c *ReadProjectCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictAnything
}

func (c *ReadProjectCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *ReadProjectCommand) Run(args []string) int {
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

	org := &scopes.Org{
		Client: client,
	}

	project := &scopes.Project{
		Id: c.flagId,
	}

	var apiErr *api.Error
	project, apiErr, err = org.ReadProject(c.Context, project)

	switch {
	case err != nil:
		c.UI.Error(fmt.Errorf("error reading project: %w", err).Error())
		return 2
	case apiErr != nil:
		c.UI.Error(pretty.Sprint(apiErr))
		return 2
	default:
		c.UI.Info(pretty.Sprint(project))
	}

	return 0
}
