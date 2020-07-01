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
	return "Authenticate the Watchtower commandline client"
}

func (c *Command) Help() string {
	helpText := `
Usage: watchtower authenticate [sub command] [options] [args]
  This command authenticates the Watchtower commandline client using a 
	specified auth method. Examples:
	  
		Authenticate with userpass auth method:

		$ watchtower authenticate userpass username=foo password=bar

  Please see the auth method subcommand help for detailed usage information.`

	return strings.TrimSpace(helpText)
}

func (c *Command) Run(args []string) int {
	return cli.RunResultHelp
}
