// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package password

import (
	"context"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
)

func init() {
	globals.RegisterPrefixSubtype(globals.PasswordAuthMethodPrefix, auth.Domain, Subtype)
	globals.RegisterPrefixSubtype(globals.PasswordAccountPreviousPrefix, auth.Domain, Subtype)
	globals.RegisterPrefixSubtype(globals.PasswordAccountPrefix, auth.Domain, Subtype)
}

// PublicId prefixes for the resources in the password package.
const (
	Subtype = globals.Subtype("password")
)

func newAuthMethodId(ctx context.Context) (string, error) {
	const op = "password.newAuthMethodId"
	id, err := db.NewPublicId(ctx, globals.PasswordAuthMethodPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	return id, nil
}

func newAccountId(ctx context.Context) (string, error) {
	const op = "password.newAccountId"
	id, err := db.NewPublicId(ctx, globals.PasswordAccountPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	return id, nil
}
