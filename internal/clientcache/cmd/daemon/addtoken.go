// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package daemon

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
	return "Add an auth token to a running boundary daemon"
}

func (c *AddTokenCommand) Help() string {
	helpText := `
Usage: boundary daemon add-token [options]

  Add an auth token to the daemon:

      $ boundary daemon add-token

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

	keyringType, tokenName, err := c.DiscoverKeyringTokenInfo()
	if err != nil {
		c.PrintCliError(err)
		return base.CommandCliError
	}

	resp, apiErr, err := c.Add(ctx, client, keyringType, tokenName)
	if err != nil {
		c.PrintCliError(err)
		return base.CommandCliError
	}
	if apiErr != nil {
		c.PrintApiError(apiErr, "Error from daemon when adding a token")
		return base.CommandApiError
	}
	switch base.Format(c.UI) {
	case "json":
		if ok := c.PrintJsonItem(resp); !ok {
			return base.CommandCliError
		}
	case "table":
		c.UI.Output("The daemon add-token operation completed successfully.")
	}
	return base.CommandSuccess
}

func (c *AddTokenCommand) Add(ctx context.Context, apiClient *api.Client, keyringType, tokenName string) (*api.Response, *api.Error, error) {
	pa := daemon.UpsertTokenRequest{
		BoundaryAddr: apiClient.Addr(),
	}
	switch keyringType {
	case "", base.NoneKeyring:
		token := apiClient.Token()
		if parts := strings.SplitN(token, "_", 4); len(parts) == 3 {
			pa.AuthTokenId = strings.Join(parts[:2], "_")
		} else {
			return nil, nil, errors.New("The found auth token is not in the proper format.")
		}
		if c.FlagOutputCurlString {
			pa.AuthToken = "/*token*/"
		} else {
			pa.AuthToken = token
		}
	default:
		at := c.ReadTokenFromKeyring(keyringType, tokenName)
		if at == nil {
			return nil, nil, errors.New("No auth token could be read from the keyring to send to daemon.")
		}
		pa.Keyring = &daemon.KeyringToken{
			KeyringType: keyringType,
			TokenName:   tokenName,
		}
		pa.AuthTokenId = at.Id
	}
	var opts []client.Option
	if c.FlagOutputCurlString {
		opts = append(opts, client.WithOutputCurlString())
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
		return nil, nil, fmt.Errorf("Error when sending request to the daemon: %w.", err)
	}
	apiErr, err := resp.Decode(nil)
	return resp, apiErr, err
}
