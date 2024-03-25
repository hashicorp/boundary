// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package ferry

import (
	"context"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/wrapper"
)

// Until we are ready to release the ferry feature, we won't output any errors
// when we fail to communicate to the ferry daemon.
const allowErrorOutput = false

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
	if err != nil && allowErrorOutput {
		baseCmd.PrintCliError(err)
		return
	}
	if token != "" {
		client.SetToken(token)
	}
	_, apiErr, err := addToken(ctx, client, baseCmd.FlagFerryDaemonPort)
	if err != nil && allowErrorOutput {
		baseCmd.PrintCliError(err)
	}
	if apiErr != nil && allowErrorOutput {
		baseCmd.PrintApiError(apiErr, "sending token to ferry daemon in the background")
	}
}
