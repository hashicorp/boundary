// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package help

import (
	"context"

	"github.com/tmc/langchaingo/llms"
)

// NewNoopModel returns a new noop model, which just returns a message that no model is configured.
func NewNoopModel(ctx context.Context) llms.Model {
	return &noopModel{}
}

type noopModel struct{}

func (*noopModel) GenerateContent(ctx context.Context, messages []llms.MessageContent, options ...llms.CallOption) (*llms.ContentResponse, error) {
	return &llms.ContentResponse{
		Choices: []*llms.ContentChoice{
			{
				Content:    "No model configured",
				StopReason: "No model configured",
			},
		},
	}, nil
}

func (*noopModel) Call(ctx context.Context, prompt string, options ...llms.CallOption) (string, error) {
	return "No model configured", nil
}
