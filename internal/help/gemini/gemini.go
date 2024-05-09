// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package gemini

import (
	"context"
	"fmt"

	"github.com/tmc/langchaingo/llms/googleai"
)

func NewModel(ctx context.Context, apiKey string, options ...googleai.Option) (*googleai.GoogleAI, error) {
	const op = "gemini.NewModel"
	if apiKey == "" {
		return nil, fmt.Errorf("%s: api key must be provided", op)
	}
	llm, err := googleai.New(ctx,
		append(
			[]googleai.Option{
				googleai.WithAPIKey(apiKey),
				googleai.WithDefaultEmbeddingModel("models/text-embedding-004"),
				googleai.WithDefaultModel("models/gemini-1.5-pro-latest"),
			},
			// Append the options to allow them to override the defaults.
			options...,
		)...,
	)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create LLM: %w", op, err)
	}
	return llm, nil
}
