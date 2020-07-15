package authenticate

import (
	"github.com/hashicorp/watchtower/internal/cmd/base"
	"github.com/mitchellh/cli"
	"github.com/mitchellh/go-wordwrap"
)

var _ cli.Command = (*Command)(nil)

type Command struct {
	*base.Command
}

func (c *Command) Synopsis() string {
	return wordwrap.WrapString("Authenticate the Watchtower commandline client", base.TermWidth)
}

func (c *Command) Help() string {
	return base.WrapForHelpText([]string{
		"Usage: watchtower authenticate [sub command] [options] [args]",
		"",
		"  This command authenticates the Watchtower commandline client using a specified auth method. Examples:",
		"",
		"    Authenticate with password auth method:",
		"",
		"      $ watchtower authenticate password -name foo -password bar",
		"",
		"  Please see the auth method subcommand help for detailed usage information.",
	})
}

func (c *Command) Run(args []string) int {
	return cli.RunResultHelp
}
