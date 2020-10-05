package authenticate

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/vault/sdk/helper/password"
	"github.com/mitchellh/cli"
	"github.com/mitchellh/go-wordwrap"
	"github.com/posener/complete"
	"github.com/zalando/go-keyring"
)

var _ cli.Command = (*PasswordCommand)(nil)
var _ cli.CommandAutocomplete = (*PasswordCommand)(nil)

var envPassword = "BOUNDARY_AUTHENTICATE_PASSWORD_PASSWORD"
var envLoginName = "BOUNDARY_AUTHENTICATE_PASSWORD_LOGIN_NAME"
var envAuthMethodId = "BOUNDARY_AUTHENTICATE_AUTH_METHOD_ID"

type PasswordCommand struct {
	*base.Command

	flagLoginName string
	flagPassword  string
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
		`    $ boundary authenticate password -auth-method-id ampw_1234567890 -login-name foo -password "bar"`,
	}) + c.Flags().Help()
}

func (c *PasswordCommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)

	f := set.NewFlagSet("Command Options")

	f.StringVar(&base.StringVar{
		Name:   "login-name",
		Target: &c.flagLoginName,
		EnvVar: envLoginName,
		Usage:  "The login name corresponding to an account within the given auth method",
	})

	f.StringVar(&base.StringVar{
		Name:   "password",
		Target: &c.flagPassword,
		EnvVar: envPassword,
		Usage:  "The password associated with the login name",
	})

	f.StringVar(&base.StringVar{
		Name:   "auth-method-id",
		EnvVar: "BOUNDARY_AUTH_METHOD_ID",
		Target: &c.FlagAuthMethodId,
		Usage:  "The auth-method resource to use for the operation",
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
	case c.flagLoginName == "":
		c.UI.Error("Login name must be provided via -login-name")
		return 1
	case c.FlagAuthMethodId == "":
		c.UI.Error("Auth method ID must be provided via -auth-method-id")
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

	client, err := c.Client(base.WithNoTokenScope(), base.WithNoTokenValue())
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error creating API client: %s", err.Error()))
		return 2
	}

	// note: Authenticate() calls SetToken() under the hood to set the
	// auth bearer on the client so we do not need to do anything with the
	// returned token after this call, so we ignore it
	result, err := authmethods.NewClient(client).Authenticate(c.Context, c.FlagAuthMethodId,
		map[string]interface{}{
			"login_name": c.flagLoginName,
			"password":   c.flagPassword,
		})
	if err != nil {
		if api.AsServerError(err) != nil {
			c.UI.Error(fmt.Sprintf("Error from controller when performing authentication: %s", err.Error()))
			return 1
		}
		c.UI.Error(fmt.Sprintf("Error trying to perform authentication: %s", err.Error()))
		return 2
	}

	token := result.GetItem().(*authtokens.AuthToken)
	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(base.WrapForHelpText([]string{
			"",
			"Authentication information:",
			fmt.Sprintf("  Account ID:      %s", token.AccountId),
			fmt.Sprintf("  Auth Method ID:  %s", token.AuthMethodId),
			fmt.Sprintf("  Expiration Time: %s", token.ExpirationTime.Local().Format(time.RFC1123)),
			fmt.Sprintf("  Token:           %s", token.Token),
			fmt.Sprintf("  User ID:         %s", token.UserId),
		}))

	case "json":
		jsonOut, err := base.JsonFormatter{}.Format(token)
		if err != nil {
			c.UI.Error(fmt.Errorf("Error formatting as JSON: %w", err).Error())
			return 1
		}
		c.UI.Output(string(jsonOut))
	}

	tokenName := "default"
	if c.Command.FlagTokenName != "" {
		tokenName = c.Command.FlagTokenName
	}
	if tokenName != "none" {
		marshaled, err := json.Marshal(token)
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
