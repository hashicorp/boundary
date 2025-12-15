// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package password

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
)

// Prefixes for private ids for types in the password package.
const (
	argon2ConfigurationPrefix = "arg2conf"
	argon2CredentialPrefix    = "arg2cred"
)

func newArgon2ConfigurationId(ctx context.Context) (string, error) {
	const op = "password.newArgon2ConfigurationId"
	id, err := db.NewPrivateId(ctx, argon2ConfigurationPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	return id, nil
}

func newArgon2CredentialId(ctx context.Context) (string, error) {
	const op = "password.newArgon2CredentialId"
	id, err := db.NewPrivateId(ctx, argon2CredentialPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	return id, nil
}
