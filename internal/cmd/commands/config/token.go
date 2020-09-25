package config

import (
	"fmt"
	"net/textproto"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var _ cli.Command = (*TokenCommand)(nil)
var _ cli.CommandAutocomplete = (*TokenCommand)(nil)

type TokenCommand struct {
	*base.Command

	Func string
}

func (c *TokenCommand) Synopsis() string {
	return fmt.Sprintf("%s sensitive values in Boundary's configuration file", textproto.CanonicalMIMEHeaderKey(c.Func))
}

func (c *TokenCommand) Help() string {
	var args []string
	switch c.Func {
	case "get-token":
		args = append(args,
			"Usage: boundary config get-token [options] [args]",
			"",
			"  Fetch a token stored by the Boundary CLI. Example:",
			"",
			`    $ boundary config get-token`,
			"",
			"  This can be useful in various situations. For example, a line such as the following could be in a shell script shared by developers, such that each developer on their own machine executing the script ends up using their own Boundary token:",
			"",
			`    $ curl -H "Authorization: Bearer $(boundary config get-token)" -H "Content-Type: application/json" http://127.0.0.1:9200/v1/roles/r_1234567890`,
			"",
			"  Note that this command keeps parity with the behavior of other Boundary commands; if the BOUNDARY_TOKEN environment variable it set, it will override the value loaded from the system store. Not only does this keep parity, but it also allows examples such as the one above to work even if there is no stored token but if an environment variable is specified.",
			"",
		)
	}

	return base.WrapForHelpText(args) + c.Flags().Help()
}

func (c *TokenCommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetNone)

	f := set.NewFlagSet("Command Options")

	f.StringVar(&base.StringVar{
		Name:   "token-name",
		Target: &c.FlagTokenName,
		EnvVar: base.EnvTokenName,
		Usage:  `If specified, the given value will be used as the name when loading the token from the system credential store. This must correspond to a name used when authenticating.`,
	})

	return set
}

func (c *TokenCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictAnything
}

func (c *TokenCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *TokenCommand) Run(args []string) (ret int) {
	f := c.Flags()
	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	client, err := c.Client()
	if err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	c.UI.Output(client.Token())

	return 0
}
