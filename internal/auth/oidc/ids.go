// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/resource"
)

func init() {
	globals.RegisterPrefixToResourceInfo(globals.OidcAuthMethodPrefix, resource.AuthMethod, auth.Domain, Subtype)
	globals.RegisterPrefixToResourceInfo(globals.OidcAccountPrefix, resource.Account, auth.Domain, Subtype)
	globals.RegisterPrefixToResourceInfo(globals.OidcManagedGroupPrefix, resource.ManagedGroup, auth.Domain, Subtype)
}

const (
	Subtype = globals.Subtype("oidc")
)

func newAuthMethodId(ctx context.Context) (string, error) {
	const op = "oidc.newAuthMethodId"
	id, err := db.NewPublicId(ctx, globals.OidcAuthMethodPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	return id, nil
}

func newAccountId(ctx context.Context, authMethodId, issuer, sub string) (string, error) {
	const op = "oidc.newAccountId"
	if authMethodId == "" {
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing auth method id")
	}
	if issuer == "" {
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing issuer")
	}
	if sub == "" {
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing subject")
	}
	id, err := db.NewPublicId(ctx, globals.OidcAccountPrefix, db.WithPrngValues([]string{authMethodId, issuer, sub}))
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	return id, nil
}

func newManagedGroupId(ctx context.Context) (string, error) {
	const op = "oidc.newManagedGroupId"
	id, err := db.NewPublicId(ctx, globals.OidcManagedGroupPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	return id, nil
}
