// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package logout

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/internal/cmd/base"
	nkeyring "github.com/jefferai/keyring"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
	zkeyring "github.com/zalando/go-keyring"
)

var (
	_ cli.Command             = (*LogoutCommand)(nil)
	_ cli.CommandAutocomplete = (*LogoutCommand)(nil)
)

type LogoutCommand struct {
	*base.Command

	Func string
}

func (c *LogoutCommand) Synopsis() string {
	return "Delete the current token within Boundary and forget it locally"
}

func (c *LogoutCommand) Help() string {
	var args []string
	args = append(args,
		"Usage: boundary logout [options]",
		"",
		"  Delete the current token (as selected by -token-name) within Boundary and forget it from the local store. Example:",
		"",
		`    $ boundary logout`,
		"",
	)

	return base.WrapForHelpText(args) + c.Flags().Help()
}

func (c *LogoutCommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetNone)

	f := set.NewFlagSet("Command Options")

	f.StringVar(&base.StringVar{
		Name:   "token-name",
		Target: &c.FlagTokenName,
		EnvVar: base.EnvTokenName,
		Usage:  `If specified, the given value will be used as the name when loading the token from the system credential store. This must correspond to a name used when authenticating.`,
	})

	f.StringVar(&base.StringVar{
		Name:    "keyring-type",
		Target:  &c.FlagKeyringType,
		Default: "auto",
		EnvVar:  base.EnvKeyringType,
		Usage:   `The type of keyring to use. Defaults to "auto" which will use the Windows credential manager, OSX keychain, or cross-platform password store depending on platform. Set to "none" to disable keyring functionality. Available types, depending on platform, are: "wincred", "keychain", "pass", and "secret-service".`,
	})

	return set
}

func (c *LogoutCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictAnything
}

func (c *LogoutCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *LogoutCommand) Run(args []string) (ret int) {
	f := c.Flags()
	if err := f.Parse(args); err != nil {
		c.PrintCliError(err)
		return base.CommandUserError
	}

	client, err := c.Client()
	if c.WrapperCleanupFunc != nil {
		defer func() {
			if err := c.WrapperCleanupFunc(); err != nil {
				c.PrintCliError(fmt.Errorf("Error cleaning kms wrapper: %w", err))
			}
		}()
	}
	if err != nil {
		c.PrintCliError(fmt.Errorf("Error reading API client: %w", err))
		return base.CommandCliError
	}

	if client.Token() == "" {
		c.PrintCliError(errors.New("Empty or no token found in store. It might have already been deleted."))
		return base.CommandUserError
	}

	id, err := base.TokenIdFromToken(client.Token())
	if err != nil {
		c.PrintCliError(err)
		return base.CommandUserError
	}

	authtokensClient := authtokens.NewClient(client)
	_, err = authtokensClient.Delete(c.Context, id)
	if apiErr := api.AsServerError(err); apiErr != nil && apiErr.Response().StatusCode() == http.StatusNotFound {
		c.UI.Output("The token was not found on the Boundary controller; proceeding to delete from the local store.")
		goto DeleteLocal
	}
	if err != nil {
		if apiErr := api.AsServerError(err); apiErr != nil {
			c.PrintApiError(apiErr, "Error from controller when performing delete on token")
			return base.CommandApiError
		}
		c.PrintCliError(fmt.Errorf("Error trying to delete auth token: %w", err))
		return base.CommandCliError
	}

	c.UI.Output("The token was successfully deleted within the Boundary controller.")

DeleteLocal:
	keyringType, tokenName, err := c.DiscoverKeyringTokenInfo()
	if err != nil {
		c.PrintCliError(fmt.Errorf("Error fetching keyring information to delete local stored token: %w", err))
		return base.CommandCliError
	}
	if keyringType == "none" ||
		tokenName == "none" ||
		keyringType == "" ||
		tokenName == "" {
		c.UI.Output("Keyring type set to none or empty; not deleting local stored token.")
		return base.CommandSuccess
	}

	switch keyringType {
	case "wincred", "keychain":
		if err := zkeyring.Delete(base.StoredTokenName, tokenName); err != nil {
			c.PrintCliError(fmt.Errorf("Error deleting auth token from %q keyring: %w", keyringType, err))
			return base.CommandCliError
		}

	default:
		krConfig := nkeyring.Config{
			LibSecretCollectionName: "login",
			PassPrefix:              "HashiCorp_Boundary",
			AllowedBackends:         []nkeyring.BackendType{nkeyring.BackendType(keyringType)},
		}

		kr, err := nkeyring.Open(krConfig)
		if err != nil {
			c.PrintCliError(fmt.Errorf("Error opening %q keyring: %w", keyringType, err))
			return base.CommandCliError
		}

		if err := kr.Remove(tokenName); err != nil {
			c.PrintCliError(fmt.Errorf("Error deleting token from %q keyring: %w", keyringType, err))
			return base.CommandCliError
		}
	}

	c.UI.Output("The token was successfully removed from the local credential store.")

	return base.CommandSuccess
}
