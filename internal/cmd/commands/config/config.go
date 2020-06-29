package config

import (
	"strings"

	"github.com/hashicorp/watchtower/internal/cmd/base"
	"github.com/mitchellh/cli"
)

var _ cli.Command = (*Command)(nil)

type Command struct {
	*base.Command
}

func (c *Command) Synopsis() string {
	return "Manage sensitive values in Watchtower's configuration files"
}

func (c *Command) Help() string {
	helpText := `
Usage: watchtower config <subcommand> [options] [args]

  This command groups subcommands for operators interacting with Watchtower's
  config files. Here are a few examples of config commands:

    Encrypt sensitive values in a config file:

    $ watchtower config encrypt config.hcl

    Decrypt sensitive values in a config file:

    $ watchtower config decrypt config.hcl

  Please see the individual subcommand help for detailed usage information.`

	return strings.TrimSpace(helpText)
}

func (c *Command) Run(args []string) int {
	return cli.RunResultHelp
}
