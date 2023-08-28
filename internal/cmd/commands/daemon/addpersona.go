// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
	"os"
	"strings"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*AddPersonaCommand)(nil)
	_ cli.CommandAutocomplete = (*AddPersonaCommand)(nil)
)

type AddPersonaCommand struct {
	*base.Command
}

func (c *AddPersonaCommand) Synopsis() string {
	return "Add a persona to a running boundary daemon"
}

func (c *AddPersonaCommand) Help() string {
	helpText := `
Usage: boundary daemon add-persona [options]

  Add a persona to the daemon:

      $ boundary daemon add-persona

  For a full list of examples, please see the documentation.

` + c.Flags().Help()
	return strings.TrimSpace(helpText)
}

func (c *AddPersonaCommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetClient | base.FlagSetOutputFormat)
	return set
}

func (c *AddPersonaCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictNothing
}

func (c *AddPersonaCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *AddPersonaCommand) Run(args []string) int {
	ctx := c.Context
	f := c.Flags()
	if err := f.Parse(args); err != nil {
		c.PrintCliError(err)
		return base.CommandUserError
	}

	apiErr, err := c.AddPersona(ctx)
	if err != nil {
		c.PrintCliError(err)
		return base.CommandCliError
	}
	if apiErr != nil {
		c.PrintApiError(apiErr, "Error from daemon when adding a persona")
		return base.CommandApiError

	}
	return base.CommandSuccess
}

func (c *AddPersonaCommand) AddPersona(ctx context.Context) (*api.Error, error) {
	const op = "daemon.(AddPersonaCommand).AddPersona"
	keyringType, tokenName, err := c.DiscoverKeyringTokenInfo()
	if err != nil {
		return nil, err
	}
	at := c.ReadTokenFromKeyring(keyringType, tokenName)
	if at == nil {
		return nil, errors.New(ctx, errors.Conflict, op, "no auth token available to send to daemon")
	}
	client, err := c.Client()
	if err != nil {
		return nil, err
	}

	pa := personaToAdd{
		KeyringType:  keyringType,
		TokenName:    tokenName,
		BoundaryAddr: client.Addr(),
		AuthTokenId:  at.Id,
	}

	dotPath, err := DefaultDotDirectory(ctx)
	if err != nil {
		return nil, err
	}

	return addPersona(ctx, dotPath, &pa)
}

func addPersona(ctx context.Context, daemonPath string, p *personaToAdd) (*api.Error, error) {
	const op = "daemon.addPersona"
	client, err := api.NewClient(nil)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	addr := SocketAddress(daemonPath)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if _, err := os.Stat(strings.TrimPrefix(addr, "unix://")); strings.HasPrefix(addr, "unix://") && err == os.ErrNotExist {
		return nil, errors.New(ctx, errors.Internal, op, "daemon unix socket is not setup")
	}
	if err := client.SetAddr(addr); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	// Because this is using the real lib it can pick up from stored locations
	// like the system keychain. Explicitly clear the token for now
	client.SetToken("")

	req, err := client.NewRequest(ctx, "POST", "/personas", p)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	return resp.Decode(&struct{}{})
}
