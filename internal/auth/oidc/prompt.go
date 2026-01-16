// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/cap/oidc"
	"google.golang.org/protobuf/proto"
)

// Prompt represents OIDC authentication prompt
type PromptParam string

const (
	// Prompt values defined by OpenID specs.
	// See: https://openid.net/specs/openid-connect-basic-1_0.html#RequestParameters
	None          PromptParam = "none"
	Login         PromptParam = "login"
	Consent       PromptParam = "consent"
	SelectAccount PromptParam = "select_account"
)

var supportedPrompts = map[PromptParam]bool{
	None:          true,
	Login:         true,
	Consent:       true,
	SelectAccount: true,
}

// SupportedPrompt returns true if the provided prompt is supported
// by boundary.
func SupportedPrompt(p PromptParam) bool {
	return supportedPrompts[p]
}

// defaultPromptTableName defines the default table name for a Prompt
const defaultPromptTableName = "auth_oidc_prompt"

// Prompt defines an prompt supported by an OIDC auth method.
// It is assigned to an OIDC AuthMethod and updates/deletes to that AuthMethod
// are cascaded to its Prompts. Prompts are value objects of an AuthMethod,
// therefore there's no need for oplog metadata, since only the AuthMethod will have
// metadata because it's the root aggregate.
type Prompt struct {
	*store.Prompt
	tableName string
}

// NewPrompt creates a new in memory prompt assigned to an OIDC
// AuthMethod. It supports no options.
func NewPrompt(ctx context.Context, authMethodId string, p PromptParam) (*Prompt, error) {
	const op = "oidc.NewPrompt"
	prompt := &Prompt{
		Prompt: &store.Prompt{
			OidcMethodId: authMethodId,
			PromptParam:  string(p),
		},
	}
	if err := prompt.validate(ctx, op); err != nil {
		return nil, err // intentionally not wrapped
	}
	return prompt, nil
}

// validate the Prompt.  On success, it will return nil.
func (s *Prompt) validate(ctx context.Context, caller errors.Op) error {
	if s.OidcMethodId == "" {
		return errors.New(ctx, errors.InvalidParameter, caller, "missing oidc auth method id")
	}
	if _, ok := supportedPrompts[PromptParam(s.PromptParam)]; !ok {
		return errors.New(ctx, errors.InvalidParameter, caller, fmt.Sprintf("unsupported prompt: %s", s.Prompt))
	}
	return nil
}

func convertToOIDCPrompts(ctx context.Context, p []string) []oidc.Prompt {
	prompts := make([]oidc.Prompt, 0, len(p))
	for _, a := range p {
		prompt := oidc.Prompt(a)
		prompts = append(prompts, prompt)
	}

	return prompts
}

// AllocPrompt makes an empty one in memory
func AllocPrompt() Prompt {
	return Prompt{
		Prompt: &store.Prompt{},
	}
}

// Clone a Prompt
func (s *Prompt) Clone() *Prompt {
	cp := proto.Clone(s.Prompt)
	return &Prompt{
		Prompt: cp.(*store.Prompt),
	}
}

// TableName returns the table name.
func (s *Prompt) TableName() string {
	if s.tableName != "" {
		return s.tableName
	}
	return defaultPromptTableName
}

// SetTableName sets the table name.
func (s *Prompt) SetTableName(n string) {
	s.tableName = n
}
