// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package request

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
)

// Validate the request.State
func (s *State) Validate(ctx context.Context) error {
	const op = "request.(State).Validate"
	if s == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing state")
	}
	if s.TokenRequestId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing token request id")
	}
	if s.CreateTime == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing create time")
	}
	if s.ExpirationTime == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing expiration time")
	}
	if s.FinalRedirectUrl == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing final redirect URL")
	}
	if s.Nonce == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing nonce")
	}
	if s.ProviderConfigHash == 0 {
		return errors.New(ctx, errors.InvalidParameter, op, "missing provider config hash")
	}
	return nil
}

// Validate the request.Wrapper
func (w *Wrapper) Validate(ctx context.Context) error {
	const op = "request.(Wrapper).Validate"
	if w == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing wrapper")
	}
	if w.AuthMethodId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing auth method id")
	}
	if w.ScopeId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	if w.WrapperKeyId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing wrapper key id")
	}
	if len(w.Ct) == 0 {
		return errors.New(ctx, errors.InvalidParameter, op, "missing ct")
	}
	return nil
}

// Validate the request.Token
func (t *Token) Validate(ctx context.Context) error {
	const op = "request.(Token).Validate"
	if t == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing token")
	}
	if t.RequestId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing request id")
	}
	if t.ExpirationTime == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing expiration time")
	}
	return nil
}
