// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package clientagentcmd

import (
	"context"
	"os"
	"strings"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/wrapper"
)

var allowErrorOutput = false

const EnvBoundaryClientAgentCliErrorOutput = "BOUNDARY_CLIENT_AGENT_CLI_ERROR_OUTPUT"

func init() {
	errOutput := os.Getenv(EnvBoundaryClientAgentCliErrorOutput)
	if strings.ToLower(errOutput) == "true" {
		allowErrorOutput = true
	}
}

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
	if err != nil && allowErrorOutput {
		baseCmd.PrintCliError(err)
		return
	}
	if token != "" {
		client.SetToken(token)
	}
	_, apiErr, err := addToken(ctx, client, baseCmd.FlagClientAgentPort)
	if err != nil && allowErrorOutput {
		baseCmd.PrintCliError(err)
	}
	if apiErr != nil && allowErrorOutput {
		baseCmd.PrintApiError(apiErr, "sending token to client agent in the background")
	}
}
