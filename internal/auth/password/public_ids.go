// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package password

import (
	"context"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/resource"
)

func init() {
	globals.RegisterPrefixToResourceInfo(globals.PasswordAuthMethodPrefix, resource.AuthMethod, auth.Domain, Subtype)
	globals.RegisterPrefixToResourceInfo(globals.PasswordAccountPreviousPrefix, resource.Account, auth.Domain, Subtype)
	globals.RegisterPrefixToResourceInfo(globals.PasswordAccountPrefix, resource.Account, auth.Domain, Subtype)
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
