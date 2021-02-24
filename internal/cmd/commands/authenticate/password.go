package authenticate

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/vault/sdk/helper/password"
	nkeyring "github.com/jefferai/keyring"
	"github.com/mitchellh/cli"
	"github.com/mitchellh/go-wordwrap"
	"github.com/posener/complete"
	zkeyring "github.com/zalando/go-keyring"
)

var (
	_ cli.Command             = (*PasswordCommand)(nil)
	_ cli.CommandAutocomplete = (*PasswordCommand)(nil)
)

var (
	envPassword     = "BOUNDARY_AUTHENTICATE_PASSWORD_PASSWORD"
	envLoginName    = "BOUNDARY_AUTHENTICATE_PASSWORD_LOGIN_NAME"
	envAuthMethodId = "BOUNDARY_AUTHENTICATE_AUTH_METHOD_ID"
)

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
		"",
		"",
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
		c.PrintCliError(err)
		return 1
	}

	switch {
	case c.flagLoginName == "":
		c.PrintCliError(errors.New("Login name must be provided via -login-name"))
		return 1
	case c.FlagAuthMethodId == "":
		c.PrintCliError(errors.New("Auth method ID must be provided via -auth-method-id"))
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
		c.PrintCliError(fmt.Errorf("Error creating API client: %w", err))
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
		if apiErr := api.AsServerError(err); apiErr != nil {
			c.PrintApiError(apiErr, "Error from controller when performing authentication")
			return 1
		}
		c.PrintCliError(fmt.Errorf("Error trying to perform authentication: %w", err))
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
		return c.PrintJsonItem(result, token)
	}

	var gotErr bool
	keyringType, tokenName, err := c.DiscoverKeyringTokenInfo()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error fetching keyring information: %s", err))
		gotErr = true
	} else if keyringType != "none" &&
		tokenName != "none" &&
		keyringType != "" &&
		tokenName != "" {
		marshaled, err := json.Marshal(token)
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error marshaling auth token to save to keyring: %s", err))
			gotErr = true
		} else {
			switch keyringType {
			case "wincred", "keychain":
				if err := zkeyring.Set("HashiCorp Boundary Auth Token", tokenName, base64.RawStdEncoding.EncodeToString(marshaled)); err != nil {
					c.UI.Error(fmt.Sprintf("Error saving auth token to %q keyring: %s", keyringType, err))
					gotErr = true
				}

			default:
				krConfig := nkeyring.Config{
					LibSecretCollectionName: "login",
					PassPrefix:              "HashiCorp_Boundary",
					AllowedBackends:         []nkeyring.BackendType{nkeyring.BackendType(keyringType)},
				}

				kr, err := nkeyring.Open(krConfig)
				if err != nil {
					c.UI.Error(fmt.Sprintf("Error opening %q keyring: %s", keyringType, err))
					gotErr = true
					break
				}

				if err := kr.Set(nkeyring.Item{
					Key:  tokenName,
					Data: []byte(base64.RawStdEncoding.EncodeToString(marshaled)),
				}); err != nil {
					c.UI.Error(fmt.Sprintf("Error storing token in %q keyring: %s", keyringType, err))
					gotErr = true
					break
				}
			}
		}
	}

	if gotErr {
		c.UI.Warn("The token printed above must be manually passed in via the BOUNDARY_TOKEN env var or -token flag. Storing the token can also be disabled via -keyring-type=none.")
	}

	return 0
}
