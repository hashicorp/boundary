// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package password

import (
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/subtypes"
)

func init() {
	if err := subtypes.Register(auth.Domain, Subtype, globals.PasswordAuthMethodPrefix, globals.OldPasswordAccountPrefix, globals.NewPasswordAccountPrefix); err != nil {
		panic(err)
	}
}

// PublicId prefixes for the resources in the password package.
const (
	Subtype = subtypes.Subtype("password")
)

func newAuthMethodId() (string, error) {
	const op = "password.newAuthMethodId"
	id, err := db.NewPublicId(globals.PasswordAuthMethodPrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, op)
	}
	return id, nil
}

func newAccountId() (string, error) {
	const op = "password.newAccountId"
	id, err := db.NewPublicId(globals.NewPasswordAccountPrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, op)
	}
	return id, nil
}
