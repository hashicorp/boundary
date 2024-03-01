// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package ferry

import (
	"context"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/wrapper"
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
		baseCmd.PrintCliError(err)
		return
	}
	if token != "" {
		client.SetToken(token)
	}
	_, apiErr, err := addToken(ctx, client, baseCmd.FlagFerryDaemonPort)
	if err != nil {
		baseCmd.PrintCliError(err)
	}
	if apiErr != nil {
		baseCmd.PrintApiError(apiErr, "sending token to ferry daemon in the background")
	}
}
