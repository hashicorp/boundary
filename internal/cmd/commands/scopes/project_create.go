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

var _ cli.Command = (*CreateProjectCommand)(nil)
var _ cli.CommandAutocomplete = (*CreateProjectCommand)(nil)

type CreateProjectCommand struct {
	*base.Command

	flagName        string
	flagDescription string
}

func (c *CreateProjectCommand) Synopsis() string {
	return "Creates a project within an organization"
}

func (c *CreateProjectCommand) Help() string {
	helpText := `
Usage: watchtower projects create

  Creates a project within the organization specified by the ID from the
  "org-id" parameter or the associated environment variable.

  Example: 

      $ watchtower projects create -org=<org_id> -name=<name>

` + c.Flags().Help()

	return strings.TrimSpace(helpText)
}

func (c *CreateProjectCommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetOutputFormat)

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

func (c *CreateProjectCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictAnything
}

func (c *CreateProjectCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *CreateProjectCommand) Run(args []string) int {
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

	org := &scopes.Organization{
		Client: client,
	}

	project := &scopes.Project{
		Name:        api.StringOrNil(c.flagName),
		Description: api.StringOrNil(c.flagDescription),
	}

	var apiErr *api.Error
	project, apiErr, err = org.CreateProject(c.Context, project)

	switch {
	case err != nil:
		c.UI.Error(fmt.Errorf("error creating project: %w", err).Error())
		return 2
	case apiErr != nil:
		c.UI.Error(pretty.Sprint(apiErr))
		return 2
	default:
		c.UI.Info(pretty.Sprint(project))
	}

	return 0
}
