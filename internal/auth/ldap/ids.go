// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/subtypes"
)

func init() {
	if err := subtypes.Register(auth.Domain, Subtype, globals.LdapAuthMethodPrefix, globals.LdapAccountPrefix, globals.LdapManagedGroupPrefix); err != nil {
		panic(err)
	}
}

const (
	Subtype = subtypes.Subtype("ldap")
)

func newAuthMethodId(ctx context.Context) (string, error) {
	const op = "ldap.newAuthMethodId"
	id, err := db.NewPublicId(ctx, globals.LdapAuthMethodPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	return id, nil
}

func newAccountId(ctx context.Context, authMethodId, loginName string) (string, error) {
	const op = "ldap.newAccountId"
	// there's a unique index on: auth method id + login name
	id, err := db.NewPublicId(ctx, globals.LdapAccountPrefix, db.WithPrngValues([]string{authMethodId, loginName}))
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	return id, nil
}

func newManagedGroupId(ctx context.Context) (string, error) {
	const op = "ldap.newManagedGroupId"
	id, err := db.NewPublicId(ctx, globals.LdapManagedGroupPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	return id, nil
}
