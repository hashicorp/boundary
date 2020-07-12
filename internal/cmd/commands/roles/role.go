package roles

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
	return wordwrap.WrapString("Manage Watchtower roles", 80)
}

func (c *Command) Help() string {
	return base.WrapForHelpText([]string{
		"Usage: watchtower role [sub command] [options] [args]",
		"",
		"  This command allows operations on Watchtower roles. Examples:",
		"",
		"    Create a role:",
		"",
		`      $ watchtower role create -name foo -description "For ProdOps usage"`,
		"",
		"    Add a grant to a role:",
		"",
		`      $ watchtower role add-grants -id r_1234567890 -grant "type=host-catalog;actions=create,delete"`,
		"",
		"  Please see the role subcommand help for detailed usage information.",
	})
}

func (c *Command) Run(args []string) int {
	return cli.RunResultHelp
}
