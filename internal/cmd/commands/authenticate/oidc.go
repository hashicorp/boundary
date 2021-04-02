package authenticate

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/mitchellh/cli"
	"github.com/mitchellh/go-wordwrap"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*OidcCommand)(nil)
	_ cli.CommandAutocomplete = (*OidcCommand)(nil)
)

type OidcCommand struct {
	*base.Command
}

func (c *OidcCommand) Synopsis() string {
	return wordwrap.WrapString("Invoke the OIDC auth method to authenticate with Boundary", base.TermWidth)
}

func (c *OidcCommand) Help() string {
	return base.WrapForHelpText([]string{
		"Usage: boundary authenticate oidc [options] [args]",
		"",
		"  Invoke the OIDC auth method to authenticate the Boundary CLI:",
		"",
		`    $ boundary authenticate oidc -auth-method-id amoidc_1234567890`,
		"",
		"",
	}) + c.Flags().Help()
}

func (c *OidcCommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)
	f := set.NewFlagSet("Command Options")

	f.StringVar(&base.StringVar{
		Name:   "auth-method-id",
		EnvVar: "BOUNDARY_AUTH_METHOD_ID",
		Target: &c.FlagAuthMethodId,
		Usage:  "The auth-method resource to use for the operation",
	})

	return set
}

func (c *OidcCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictAnything
}

func (c *OidcCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *OidcCommand) Run(args []string) int {
	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.PrintCliError(err)
		return base.CommandUserError
	}

	switch {
	case c.FlagAuthMethodId == "":
		c.PrintCliError(errors.New("Auth method ID must be provided via -auth-method-id"))
		return base.CommandUserError
	}

	client, err := c.Client(base.WithNoTokenScope(), base.WithNoTokenValue())
	if err != nil {
		c.PrintCliError(fmt.Errorf("Error creating API client: %w", err))
		return base.CommandCliError
	}

	result, err := authmethods.NewClient(client).Authenticate(c.Context, c.FlagAuthMethodId, "start", nil)
	if err != nil {
		if apiErr := api.AsServerError(err); apiErr != nil {
			c.PrintApiError(apiErr, "Error from controller when performing authentication start")
			return base.CommandApiError
		}
		c.PrintCliError(fmt.Errorf("Error trying to perform authentication start: %w", err))
		return base.CommandCliError
	}

	startResp := new(authmethods.OidcAuthMethodAuthenticateStartResponse)
	if err := json.Unmarshal(result.GetRawAttributes(), startResp); err != nil {
		c.PrintCliError(fmt.Errorf("Error trying to decode authenticate start response: %w", err))
		return base.CommandCliError
	}

	c.UI.Output(startResp.AuthUrl)

	/*
		// Leg 3: swap for the token
		token := new(authtokens.AuthToken)
		if err := json.Unmarshal(result.GetRawAttributes(), token); err != nil {
			c.PrintCliError(fmt.Errorf("Error trying to decode response as an auth token: %w", err))
			return base.CommandCliError
		}

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
			if ok := c.PrintJsonItem(&dummyGenericResponse{
				item:     token,
				response: result.GetResponse(),
			}, token); !ok {
				return base.CommandCliError
			}
			return base.CommandSuccess
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

	*/
	return base.CommandSuccess
}
