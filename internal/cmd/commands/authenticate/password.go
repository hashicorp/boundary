package authenticate

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/vault/sdk/helper/password"
	"github.com/kr/pretty"
	"github.com/mitchellh/cli"
	"github.com/mitchellh/go-wordwrap"
	"github.com/posener/complete"
	"github.com/zalando/go-keyring"
)

var _ cli.Command = (*PasswordCommand)(nil)
var _ cli.CommandAutocomplete = (*PasswordCommand)(nil)

var envPassword = "BOUNDARY_AUTHENTICATE_PASSWORD"
var envName = "BOUNDARY_AUTHENTICATE_NAME"
var envMethodId = "BOUNDARY_AUTHENTICATE_METHOD_ID"

type PasswordCommand struct {
	*base.Command

	flagName     string
	flagPassword string
	flagMethodId string
}

func (c *PasswordCommand) Synopsis() string {
	return wordwrap.WrapString("Invoke the password auth method to authenticate with Boundary", base.TermWidth)
}

func (c *PasswordCommand) Help() string {
	return base.WrapForHelpText([]string{
		"Usage: boundary authenticate password [options] [args]",
		"",
		"  Invoke the password auth method to authenticate the Boundary CLI:",
		"",
		"    $ boundary authenticate password -name=foo -password=bar",
		"",
		"  If more than one instance of the password auth method exists, use the -method-id flag:",
		"",
		`    $ boundary authenticate password -method-id am_12345 -name foo -password "bar"`,
	}) + c.Flags().Help()
}

func (c *PasswordCommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)

	f := set.NewFlagSet("Command Options")

	f.StringVar(&base.StringVar{
		Name:   "name",
		Target: &c.flagName,
		EnvVar: envName,
		Usage:  "Login name",
	})

	f.StringVar(&base.StringVar{
		Name:   "password",
		Target: &c.flagPassword,
		EnvVar: envPassword,
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

func (c *PasswordCommand) Run(args []string) int {
	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	switch {
	case c.flagName == "":
		c.UI.Error("Name must be provided via -name")
		return 1
	case c.flagMethodId == "":
		c.UI.Error("Auth method ID must be provided via -method-id")
		return 1
	}

	if c.flagPassword == "" {
		fmt.Print("Password is not set as flag or in env, please enter it now (will be hidden): ")
		value, err := password.Read(os.Stdin)
		fmt.Print("\n")
		if err != nil {
			c.UI.Error(fmt.Sprintf("An error occurred attempting to read the password. The raw error message is shown below but usually this is because you attempted to pipe a value into the command or you are executing outside of a terminal (TTY). The raw error was:\n\n%s", err.Error()))
			return 2
		}
		c.flagPassword = strings.TrimSpace(value)
	}

	client, err := c.Client()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error creating API client: %s", err.Error()))
		return 2
	}

	// note: Authenticate() calls SetToken() under the hood to set the
	// auth bearer on the client so we do not need to do anything with the
	// returned token after this call, so we ignore it
	result, apiErr, err := authmethods.NewAuthMethodsClient(client).Authenticate(c.Context, c.flagMethodId, c.flagName, c.flagPassword)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error trying to perform authentication: %s", err.Error()))
		return 2
	}
	if apiErr != nil {
		c.UI.Error(fmt.Sprintf("Error from controller when performing authentication: %s", pretty.Sprint(apiErr)))
		return 1
	}

	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(base.WrapForHelpText([]string{
			"",
			"Authentication information:",
			fmt.Sprintf("  Token:           %s", result.Token),
			fmt.Sprintf("  User ID:         %s", result.UserId),
			fmt.Sprintf("  Expiration Time: %s", result.ExpirationTime.Local().Format(time.RFC3339)),
		}))
	}

	tokenName := "default"
	if c.Command.FlagTokenName != "" {
		tokenName = c.Command.FlagTokenName
	}
	if tokenName != "none" {
		marshaled, err := json.Marshal(result)
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error marshaling auth token to save to system credential store: %s", err))
			return 1
		}
		if err := keyring.Set("HashiCorp Boundary Auth Token", tokenName, base64.RawStdEncoding.EncodeToString(marshaled)); err != nil {
			c.UI.Error(fmt.Sprintf("Error saving auth token to system credential store: %s", err))
			return 1
		}
	}

	return 0
}
