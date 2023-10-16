// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
	"os"
	"strings"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/internal/clientcache/internal/daemon"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/version"
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

	apiErr, err := c.Add(ctx)
	if err != nil {
		c.PrintCliError(err)
		return base.CommandCliError
	}
	if apiErr != nil {
		c.PrintApiError(apiErr, "Error from daemon when adding a token")
		return base.CommandApiError

	}
	return base.CommandSuccess
}

func (c *AddTokenCommand) Add(ctx context.Context) (*api.Error, error) {
	const op = "daemon.(AddTokenCommand).Add"
	client, err := c.Client()
	if err != nil {
		return nil, err
	}

	keyringType, tokenName, err := c.DiscoverKeyringTokenInfo()
	if err != nil {
		return nil, err
	}

	pa := daemon.UpsertTokenRequest{
		BoundaryAddr: client.Addr(),
	}
	switch keyringType {
	case "", base.NoneKeyring:
		keyringType = base.NoneKeyring
		token := client.Token()
		if parts := strings.SplitN(token, "_", 4); len(parts) == 3 {
			pa.AuthTokenId = strings.Join(parts[:2], "_")
		} else {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "found auth token is not in the proper format")
		}
		pa.AuthToken = token
	default:
		at := c.ReadTokenFromKeyring(keyringType, tokenName)
		if at == nil {
			return nil, errors.New(ctx, errors.Conflict, op, "no auth token available to send to daemon")
		}
		pa.Keyring = &daemon.KeyringToken{
			KeyringType: keyringType,
			TokenName:   tokenName,
		}
		pa.AuthTokenId = at.Id
	}

	dotPath, err := DefaultDotDirectory(ctx)
	if err != nil {
		return nil, err
	}

	return addToken(ctx, dotPath, &pa)
}

func addToken(ctx context.Context, daemonPath string, p *daemon.UpsertTokenRequest) (*api.Error, error) {
	const op = "daemon.addToken"
	client, err := api.NewClient(nil)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	addr := daemon.SocketAddress(daemonPath)
	_, err = os.Stat(strings.TrimPrefix(addr, "unix://"))
	if strings.HasPrefix(addr, "unix://") && err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if err := client.SetAddr(addr); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	// Because this is using the real lib it can pick up from stored locations
	// like the system keychain. Explicitly clear the token for now
	client.SetToken("")

	req, err := client.NewRequest(ctx, "POST", "/tokens", p)
	if err != nil {
		return nil, err
	}
	req.Header.Add(daemon.VersionHeaderKey, version.Get().VersionNumber())
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	return resp.Decode(&struct{}{})
}
