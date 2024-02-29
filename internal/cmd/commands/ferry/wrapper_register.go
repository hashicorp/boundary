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
	client, err := baseCmd.Client()
	if err != nil {
		// print this error out to stderr?
		return
	}
	if token != "" {
		client.SetToken(token)
	}

	// We do not want to print errors out from our background interactions with
	// the daemon so use the silentUi to toss out anything that shouldn't be used
	_, apiErr, err := AddToken(ctx, silentUi(), client, baseCmd.FlagFerryDaemonPort)
	_, _ = apiErr, err
}

// silentUi should not be used in situations where the UI is expected to be
// prompt the user for input.
func silentUi() *cli.BasicUi {
	return &cli.BasicUi{
		Writer:      io.Discard,
		ErrorWriter: io.Discard,
	}
}
