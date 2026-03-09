// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/internal/clientcache/internal/client"
	"github.com/hashicorp/boundary/internal/clientcache/internal/daemon"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*AddTokenCommand)(nil)
	_ cli.CommandAutocomplete = (*AddTokenCommand)(nil)
)

type AddTokenCommand struct {
	*base.Command
}

func (c *AddTokenCommand) Synopsis() string {
	return "Add an auth token to a running boundary cache"
}

func (c *AddTokenCommand) Help() string {
	helpText := `
Usage: boundary cache add-token [options]

  Add an auth token to the cache:

      $ boundary cache add-token

  For a full list of examples, please see the documentation.

` + c.Flags().Help()
	return strings.TrimSpace(helpText)
}

func (c *AddTokenCommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetOutputFormat)
	f := set.NewFlagSet("Connection Options")

	f.StringVar(&base.StringVar{
		Name:       base.FlagNameAddr,
		Target:     &c.FlagAddr,
		EnvVar:     api.EnvBoundaryAddr,
		Completion: complete.PredictAnything,
		Usage:      "Addr of the Boundary controller, as a complete URL (e.g. https://boundary.example.com:9200).",
	})

	f = set.NewFlagSet("Client Options")

	f.StringVar(&base.StringVar{
		Name:   "token-name",
		Target: &c.FlagTokenName,
		EnvVar: base.EnvTokenName,
		Usage:  `If specified, the given value will be used as the name when storing the token in the system credential store. This can allow switching user identities for different commands.`,
	})

	f.StringVar(&base.StringVar{
		Name:    "keyring-type",
		Target:  &c.FlagKeyringType,
		Default: "auto",
		EnvVar:  base.EnvKeyringType,
		Usage:   `The type of keyring to use. Defaults to "auto" which will use the Windows credential manager, OSX keychain, or cross-platform password store depending on platform. Set to "none" to disable keyring functionality. Available types, depending on platform, are: "wincred", "keychain", "pass", and "secret-service".`,
	})

	f.StringVar(&base.StringVar{
		Name:   "token",
		Target: &c.FlagToken,
		Usage:  `A URL pointing to a file on disk (file://) from which a token will be read or an env var (env://) from which the token will be read. Overrides the "token-name" parameter.`,
	})

	f.BoolVar(&base.BoolVar{
		Name:   "output-curl-string",
		Target: &c.FlagOutputCurlString,
		Usage:  "Instead of executing the request, print an equivalent cURL command string and exit.",
	})

	return set
}

func (c *AddTokenCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictNothing
}

func (c *AddTokenCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *AddTokenCommand) Run(args []string) int {
	ctx := c.Context
	f := c.Flags()
	if err := f.Parse(args); err != nil {
		c.PrintCliError(err)
		return base.CommandUserError
	}
	client, err := c.Client()
	if err != nil {
		c.PrintCliError(err)
		return base.CommandCliError
	}

	// We ignore the error here since not having a keyring on the platform
	// returns an error but can be treated as the keyring type being set to
	// none.
	keyringType, tokenName, _ := c.DiscoverKeyringTokenInfo()

	resp, apiErr, err := c.Add(ctx, c.UI, client, keyringType, tokenName)
	if err != nil {
		c.PrintCliError(err)
		return base.CommandCliError
	}
	if apiErr != nil {
		c.PrintApiError(apiErr, "Error from cache when adding a token")
		return base.CommandApiError
	}
	switch base.Format(c.UI) {
	case "json":
		if ok := c.PrintJsonItem(resp); !ok {
			return base.CommandCliError
		}
	case "table":
		c.UI.Output("The cache add-token operation completed successfully.")
	}
	return base.CommandSuccess
}

// Add builds the UpsertTokenRequest using the client's address and token,
// and trying to leverage the keyring. It then sends the request to the cache.
// The passed in cli.Ui is used to print out any errors when looking up the
// auth token from the keyring. This allows background operations calling this
// method to pass in a silent UI to suppress any output.
func (c *AddTokenCommand) Add(ctx context.Context, ui cli.Ui, apiClient *api.Client, keyringType, tokenName string) (*api.Response, *api.Error, error) {
	pa := daemon.UpsertTokenRequest{
		BoundaryAddr: apiClient.Addr(),
	}
	token := apiClient.Token()
	if token == "" {
		return nil, nil, errors.New("The client auth token is empty.")
	}

	if parts := strings.SplitN(token, "_", 4); len(parts) == 3 {
		pa.AuthTokenId = strings.Join(parts[:2], "_")
	} else {
		return nil, nil, errors.New("The client provided auth token is not in the proper format.")
	}
	var opts []client.Option
	if c.FlagOutputCurlString {
		opts = append(opts, client.WithOutputCurlString())
		pa.AuthToken = "/*token*/"
	} else {
		pa.AuthToken = token
	}

	switch keyringType {
	case "", base.NoneKeyring:
		// we don't need to do anything else in this situation since the keyring
		// doesn't play a part in the request.
	default:
		// Just because the keyring type is set doesn't mean the token to add
		// is contained in it. For example, if the token was intercepted
		// from an authentication request with '-format json' then token is
		// not stored in the keyring, even if a keyring is provided.

		// Try to read the token from the keyring in a best effort way. Ignore
		// any errors since the keyring may not be present on the system.
		at, _ := base.ReadTokenFromKeyring(ui, keyringType, tokenName)
		if at != nil && (token == "" || pa.AuthTokenId == at.Id) {
			pa.Keyring = &daemon.KeyringToken{
				KeyringType: keyringType,
				TokenName:   tokenName,
			}
			// since the auth token is stored in the keyring, we can share it
			// through the keyring instead of passing it through the request.
			pa.AuthToken = ""
		}
	}

	dotPath, err := DefaultDotDirectory(ctx)
	if err != nil {
		return nil, nil, err
	}
	return addToken(ctx, dotPath, &pa, opts...)
}

func addToken(ctx context.Context, daemonPath string, p *daemon.UpsertTokenRequest, opt ...client.Option) (*api.Response, *api.Error, error) {
	addr := daemon.SocketAddress(daemonPath)
	_, err := os.Stat(addr.Path)
	if addr.Scheme == "unix" && err != nil {
		return nil, nil, fmt.Errorf("Error when detecting if the domain socket is present: %w.", err)
	}

	c, err := client.New(ctx, addr)
	if err != nil {
		return nil, nil, fmt.Errorf("Error when making a new client: %w.", err)
	}
	resp, err := c.Post(ctx, "/v1/tokens", p, opt...)
	if err != nil {
		return nil, nil, fmt.Errorf("Error when sending request to the cache: %w.", err)
	}
	apiErr, err := resp.Decode(nil)
	return resp, apiErr, err
}
