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
	set := c.FlagSet(base.FlagSetClient | base.FlagSetOutputFormat)
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
		var opt []base.Option
		if r := resp.Response; r != nil {
			opt = append(opt, base.WithStatusCode(r.StatusCode))
		}
		if ok := c.PrintJson(resp.Body(), opt...); !ok {
			return base.CommandCliError
		}
	case "table":
		c.UI.Output("The daemon add-token operation completed successfully.")
	}
	return base.CommandSuccess
}

func (c *AddTokenCommand) Add(ctx context.Context, client *api.Client, keyringType, tokenName string) (*client.Response, *api.Error, error) {
	pa := daemon.UpsertTokenRequest{
		BoundaryAddr: client.Addr(),
	}
	switch keyringType {
	case "", base.NoneKeyring:
		token := client.Token()
		if parts := strings.SplitN(token, "_", 4); len(parts) == 3 {
			pa.AuthTokenId = strings.Join(parts[:2], "_")
		} else {
			return nil, nil, errors.New("The found auth token is not in the proper format.")
		}
		pa.AuthToken = token
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

	dotPath, err := DefaultDotDirectory(ctx)
	if err != nil {
		return nil, nil, err
	}

	return addToken(ctx, dotPath, &pa)
}

func addToken(ctx context.Context, daemonPath string, p *daemon.UpsertTokenRequest) (*client.Response, *api.Error, error) {
	addr, err := daemon.SocketAddress(daemonPath)
	if err != nil {
		return nil, nil, fmt.Errorf("Error when retrieving the socket address: %w", err)
	}
	_, err = os.Stat(addr.Path)
	if addr.Scheme == "unix" && err != nil {
		return nil, nil, fmt.Errorf("Error when detecting if the domain socket is present: %w.", err)
	}

	c, err := client.New(ctx, addr)
	if err != nil {
		return nil, nil, fmt.Errorf("Error when making a new client: %w.", err)
	}
	resp, apiErr, err := c.Post(ctx, "/v1/tokens", p)
	if err != nil {
		return nil, nil, fmt.Errorf("Error when sending request to the daemon: %w.", err)
	}
	return resp, apiErr, nil
}
