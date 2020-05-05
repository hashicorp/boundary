package hosts

import (
	"fmt"
	"strings"

	"github.com/hashicorp/watchtower/api"
	"github.com/hashicorp/watchtower/api/hosts"
	"github.com/hashicorp/watchtower/internal/cmd/base"
	"github.com/kr/pretty"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var _ cli.Command = (*CreateCommand)(nil)
var _ cli.CommandAutocomplete = (*CreateCommand)(nil)

type CreateCommand struct {
	*base.Command

	flagAddress string
	flagName    string
	flagCatalog string
}

func (c *CreateCommand) Synopsis() string {
	return "Creates a host in the given host catalog"
}

func (c *CreateCommand) Help() string {
	helpText := `
Usage: watchtower hosts create

  Creates a host in the given host catalog. This command will result in an
  error for any catalog that does not support manual host creation.

  Example: 

      $ watchtower hosts create -catalog=<id> -address=<addr> -name=<name>

` + c.Flags().Help()

	return strings.TrimSpace(helpText)
}

func (c *CreateCommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetOutputFormat)

	f := set.NewFlagSet("Command Options")

	f.StringVar(&base.StringVar{
		Name:       "address",
		Target:     &c.flagAddress,
		Completion: complete.PredictAnything,
		Usage:      "The host's address; can be an IP address or DNS name",
	})

	f.StringVar(&base.StringVar{
		Name:       "name",
		Target:     &c.flagName,
		Completion: complete.PredictAnything,
		Usage:      "An optional name assigned to the host for display purposes",
	})

	f.StringVar(&base.StringVar{
		Name:       "catalog",
		Target:     &c.flagCatalog,
		Completion: complete.PredictAnything,
		Usage:      "The ID of the host catalog in which the host should be created",
	})

	return set
}

func (c *CreateCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictAnything
}

func (c *CreateCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *CreateCommand) Run(args []string) int {
	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	switch {
	case c.flagCatalog == "":
		c.UI.Error("Catalog ID must be provided via -catalog")
		return 1
	case c.flagAddress == "":
		c.UI.Error("Host address must be provided via -address")
		return 1
	}

	client, err := c.Client()
	if err != nil {
		c.UI.Error(err.Error())
		return 2
	}

	catalog := &hosts.HostCatalog{
		Client: client,
		Id:     api.String(c.flagCatalog),
	}

	host := &hosts.Host{
		Name:    api.StringOrNil(c.flagName),
		Address: api.String(c.flagAddress),
	}

	var apiErr *api.Error
	host, apiErr, err = catalog.CreateHost(c.Context, host)

	switch {
	case err != nil:
		c.UI.Error(fmt.Errorf("error creating host: %w", err).Error())
		return 2
	case apiErr != nil:
		c.UI.Error(pretty.Sprint(apiErr))
		return 2
	default:
		c.UI.Info(pretty.Sprint(host))
	}

	return 0
}
