// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package clientagentcmd

import (
	"context"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/wrapper"
)

func init() {
	if err := wrapper.RegisterSuccessfulCommandCallback("client-agent", hook); err != nil {
		panic(err)
	}
}

func hook(ctx context.Context, baseCmd *base.Command, token string) {
	if baseCmd.FlagSkipClientAgent {
		return
	}
	client, err := baseCmd.Client()
	if err != nil && baseCmd.FlagOutputClientAgentCliError {
		baseCmd.PrintCliError(err)
		return
	}
	if token != "" {
		client.SetToken(token)
	}
	_, apiErr, err := addToken(ctx, client, baseCmd.FlagClientAgentPort)
	if err != nil && baseCmd.FlagOutputClientAgentCliError {
		baseCmd.PrintCliError(err)
	}
	if apiErr != nil && baseCmd.FlagOutputClientAgentCliError {
		baseCmd.PrintApiError(apiErr, "sending token to client agent in the background")
	}
}
