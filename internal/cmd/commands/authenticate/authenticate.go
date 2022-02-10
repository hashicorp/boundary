package authenticate

import (
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/mitchellh/cli"
	"github.com/mitchellh/go-wordwrap"
)

var _ cli.Command = (*Command)(nil)

type Command struct {
	*base.Command
}

func (c *Command) Synopsis() string {
	return wordwrap.WrapString("Authenticate the Boundary command-line client", base.TermWidth)
}

func (c *Command) Help() string {
	return base.WrapForHelpText([]string{
		"Usage: boundary authenticate [sub command] [options] [args]",
		"",
		"  This command authenticates the Boundary commandline client using a specified auth method. Examples:",
		"",
		"    Authenticate with a password auth method:",
		"",
		"      $ boundary authenticate password -auth-method-id ampw_1234567890 -login-name foo",
		"",
		"    Authenticate with an OIDC auth method:",
		"",
		"      $ boundary authenticate oidc -auth-method-id amoidc_1234567890",
		"",
		"  Please see the auth method subcommand help for detailed usage information.",
	})
}

func (c *Command) Run(args []string) int {
	return cli.RunResultHelp
}
