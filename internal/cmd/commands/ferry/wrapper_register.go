// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package ferry

import (
	"context"
	"io"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/wrapper"
	"github.com/mitchellh/cli"
)

func init() {
	if err := wrapper.RegisterSuccessfulCommandCallback("ferry", hook); err != nil {
		panic(err)
	}
}

func hook(ctx context.Context, baseCmd *base.Command, token string) {
	if baseCmd.FlagSkipFerry {
		return
	}
	addTokenToFerry(ctx, baseCmd, token)
}

// silentUi should not be used in situations where the UI is expected to be
// prompt the user for input.
func silentUi() *cli.BasicUi {
	return &cli.BasicUi{
		Writer:      io.Discard,
		ErrorWriter: io.Discard,
	}
}

// addTokenToFerry runs AddTokenCommand with the token used in, or retrieved by
// the wrapped command.
func addTokenToFerry(ctx context.Context, baseCmd *base.Command, token string) bool {
	com := AddTokenCommand{Command: base.NewCommand(baseCmd.UI)}
	com.FlagFerryDaemonPort = baseCmd.FlagFerryDaemonPort

	client, err := baseCmd.Client()
	if err != nil {
		return false
	}
	if token != "" {
		client.SetToken(token)
	}

	// We do not want to print errors out from our background interactions with
	// the daemon so use the silentUi to toss out anything that shouldn't be used
	_, apiErr, err := com.Add(ctx, silentUi(), client)
	return err == nil && apiErr == nil
}
