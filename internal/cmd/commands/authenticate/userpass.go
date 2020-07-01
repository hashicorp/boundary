package authenticate

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/watchtower/internal/cmd/base"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var _ cli.Command = (*PasswordCommand)(nil)
var _ cli.CommandAutocomplete = (*PasswordCommand)(nil)

var envPassword = "WATCHTOWER_PASSWORD_PASSWORD"

type PasswordCommand struct {
	*base.Command

	flagUsername string
	flagPassword string
	flagID       string
}

func (c *PasswordCommand) Synopsis() string {
	return "Invoke the password auth method to authenticate with Watchtower"
}

func (c *PasswordCommand) Help() string {
	return strings.TrimSpace(`
Usage: watchtower authenticate password [options] [args]

  Invoke the password auth method to authenticate the Watchtower
  commandline:

	$ watchtower authenticate password -username=foo -password=bar

	If more than one instance of the password auth method exists, use 
	the -id flag:

	$ watchtower authenticate password -id=am_12345 -username=foo -password=bar
`)
}

func (c *PasswordCommand) Flags() *base.FlagSets {
	set := c.FlagSet(0)

	f := set.NewFlagSet("Command Options")

	f.StringVar(&base.StringVar{
		Name:   "username",
		Target: &c.flagUsername,
		Usage:  "Username for the password auth method",
	})

	f.StringVar(&base.StringVar{
		Name:   "password",
		Target: &c.flagPassword,
		Usage:  "Password for the password auth method",
	})

	f.StringVar(&base.StringVar{
		Name:   "id",
		Target: &c.flagPassword,
		Usage:  "ID is only required if more than one instance of the auth method exists",
	})

	return set
}

func (c *PasswordCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictAnything
}

func (c *PasswordCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *PasswordCommand) Run(args []string) (ret int) {
	if c.flagPassword == "" {
		c.flagPassword = os.Getenv(envPassword)
	}

	if c.flagPassword == "" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Password is not set as flag or in env, please enter it now: ")
		text, _ := reader.ReadString('\n')
		c.flagPassword = text
	}

	fmt.Printf("password is set to '%s'", c.flagPassword)

	return ret
}
