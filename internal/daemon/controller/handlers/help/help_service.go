// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package help

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/tmc/langchaingo/llms"
	"google.golang.org/grpc/codes"
)

const promptTemplate = `
You are a knowledgeable support engineer for the HashiCorp Boundary product. You specialize in answering questions that customers have about using the Boundary product using clear and concise answers. Include code examples where appropriate for the question. Included below are some relevant documents from the Boundary product documentation in markdown format.

%s

Using the information above, answer the following question:

%s
`

type Searcher interface {
	FindTopDocsForQuery(context.Context, string) ([]string, error)
}

// Service handles request as described by the pbs.HelpServiceServer interface.
type Service struct {
	pbs.UnsafeHelpServiceServer

	llm      llms.Model
	searcher Searcher
}

var _ pbs.HelpServiceServer = (*Service)(nil)

// NewService returns a help service which handles help related requests to boundary.
func NewService(ctx context.Context, llm llms.Model, searcher Searcher) (Service, error) {
	return Service{llm: llm, searcher: searcher}, nil
}

// Help implements the interface pbs.HelpServiceServer.
func (s Service) Help(ctx context.Context, req *pbs.HelpRequest) (*pbs.HelpResponse, error) {
	if req.Query == "" {
		return nil, handlers.InvalidArgumentErrorf("Invalid request", map[string]string{"query": "This field is required."})
	}

	docs, err := s.searcher.FindTopDocsForQuery(ctx, req.Query)
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "failed to search for docs: %v", err)
	}

	fullPrompt := fmt.Sprintf(promptTemplate, strings.Join(docs, "\n"), req.Query)

	answer, err := llms.GenerateFromSinglePrompt(ctx, s.llm, fullPrompt)
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "failed to generate response from LLM: %v", err)
	}

	return &pbs.HelpResponse{
		Answer: answer,
	}, nil
}
