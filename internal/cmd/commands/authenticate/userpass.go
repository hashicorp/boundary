package config

import (
	"strings"

	"github.com/hashicorp/watchtower/internal/cmd/base"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var _ cli.Command = (*UserpassCommand)(nil)
var _ cli.CommandAutocomplete = (*UserpassCommand)(nil)

type UserpassCommand struct {
	*base.Command

	flagUsername string
	flagPassword string
}

func (c *UserpassCommand) Synopsis() string {
	return "Invoke the userpass auth method to authenticate with Watchtower"
}

func (c *UserpassCommand) Help() string {
	return strings.TrimSpace(`
Usage: watchtower authenticate userpass [options] [args]

  Invoke the userpass auth method to authenticate the Watchtower
	commandline. 

	$ watchtower authenticate userpass -username=foo -password=bar
`)
}

func (c *UserpassCommand) Flags() *base.FlagSets {
	set := c.FlagSet(0)

	f := set.NewFlagSet("Command Options")

	f.StringVar(&base.StringVar{
		Name:   "username",
		Target: &c.flagUsername,
		Usage:  "Username for the userpass auth method",
	})

	f.StringVar(&base.StringVar{
		Name:   "password",
		Target: &c.flagPassword,
		Usage:  "Password for the userpass auth method",
	})

	return set
}

func (c *UserpassCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictAnything
}

func (c *UserpassCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *UserpassCommand) Run(args []string) (ret int) {
	return ret
}
