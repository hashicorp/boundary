// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package auth

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/util"
)

// AuthMethodSubtypeService defines the expected signature for an auth method repository.
type AuthMethodSubtypeService interface {
	EstimatedAuthMethodCount(context.Context) (int, error)
	ListDeletedAuthMethodIds(context.Context, time.Time, ...Option) ([]string, error)
	ListAuthMethods(context.Context, []string, ...Option) ([]AuthMethod, error)
}

// AuthMethodService coordinates calls to across different subtype repositories
// to gather information about all AuthMethods.
type AuthMethodService struct {
	ldapRepo     AuthMethodSubtypeService
	oidcRepo     AuthMethodSubtypeService
	passwordRepo AuthMethodSubtypeService
	writer       db.Writer
}

// NewAuthMethodService returns a new AuthMethod service.
func NewAuthMethodService(
	ctx context.Context,
	writer db.Writer,
	ldapRepo AuthMethodSubtypeService,
	oidcRepo AuthMethodSubtypeService,
	passwordRepo AuthMethodSubtypeService,
) (*AuthMethodService, error) {
	const op = "AuthMethod.NewAuthMethodService"
	switch {
	case util.IsNil(writer):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing DB writer")
	case util.IsNil(ldapRepo):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing ldap repo")
	case util.IsNil(oidcRepo):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing oidc repo")
	case util.IsNil(passwordRepo):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing password repo")
	}
	return &AuthMethodService{
		ldapRepo:     ldapRepo,
		oidcRepo:     oidcRepo,
		passwordRepo: passwordRepo,
		writer:       writer,
	}, nil
}
