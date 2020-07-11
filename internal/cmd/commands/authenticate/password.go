package authenticate

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/vault/sdk/helper/password"
	"github.com/hashicorp/watchtower/api/scopes"
	"github.com/hashicorp/watchtower/internal/cmd/base"
	"github.com/mitchellh/cli"
	"github.com/mitchellh/go-wordwrap"
	"github.com/posener/complete"
)

var _ cli.Command = (*PasswordCommand)(nil)
var _ cli.CommandAutocomplete = (*PasswordCommand)(nil)

var envPassword = "WATCHTOWER_AUTHENTICATE_PASSWORD"
var envName = "WATCHTOWER_AUTHENTICATE_NAME"
var envMethodId = "WATCHTOWER_AUTHENTICATE_METHOD_ID"

type PasswordCommand struct {
	*base.Command

	flagName     string
	flagPassword string
	flagMethodId string
}

func (c *PasswordCommand) Synopsis() string {
	return wordwrap.WrapString("Invoke the password auth method to authenticate with Watchtower", 80)
}

func (c *PasswordCommand) Help() string {
	return base.WrapForHelpText([]string{
		"Usage: watchtower authenticate password [options] [args]",
		"  Invoke the password auth method to authenticate the Watchtower CLI:",
		"    $ watchtower authenticate password -username=foo -password=bar",
		"  If more than one instance of the password auth method exists, use the -method-id flag:",
		"    $ watchtower authenticate password -method-id=am_12345 -username=foo -password=bar",
	})
}

func (c *PasswordCommand) Flags() *base.FlagSets {
	set := c.FlagSet(0)

	f := set.NewFlagSet("Command Options")

	f.StringVar(&base.StringVar{
		Name:   "name",
		Target: &c.flagName,
		Usage:  "Login name",
	})

	f.StringVar(&base.StringVar{
		Name:   "password",
		Target: &c.flagPassword,
		Usage:  "Password",
	})

	f.StringVar(&base.StringVar{
		Name:   "method-id",
		Target: &c.flagMethodId,
		EnvVar: envMethodId,
		Usage:  "Specify if more than one instance of a password auth method exists in the given org",
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
		fmt.Print("Password is not set as flag or in env, please enter it now (will be hidden): ")
		value, err := password.Read(os.Stdin)
		fmt.Print("\n")
		if err != nil {
			c.UI.Error(base.WrapAtLength(fmt.Sprintf("An error occurred attempting to read the password. The raw error message is shown below but usually this is because you attempted to pipe a value into the command or you are executing outside of a terminal (TTY). The raw error was:\n\n%s", err.Error())))
			return 1
		}
		c.flagPassword = strings.TrimSpace(value)
	}

	client, err := c.Client()
	if err != nil {
		fmt.Printf(err.Error())
		return 1
	}

	org := &scopes.Org{
		Client: client,
	}
	ctx := context.Background()

	// note: Authenticate() calls SetToken() under the hood to set the
	// auth bearer on the client so we do not need to do anything with the
	// returned token after this call, so we ignore it
	_, apiErr, err := org.Authenticate(ctx, c.flagMethodId, c.flagName, c.flagPassword)
	if apiErr != nil {
		fmt.Printf(*apiErr.Message)
		return 1
	}
	if err != nil {
		fmt.Printf(err.Error())
		return 1
	}

	return ret
}
