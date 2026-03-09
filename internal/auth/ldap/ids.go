// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/resource"
)

func init() {
	globals.RegisterPrefixToResourceInfo(globals.LdapAuthMethodPrefix, resource.AuthMethod, auth.Domain, Subtype)
	globals.RegisterPrefixToResourceInfo(globals.LdapAccountPrefix, resource.Account, auth.Domain, Subtype)
	globals.RegisterPrefixToResourceInfo(globals.LdapManagedGroupPrefix, resource.ManagedGroup, auth.Domain, Subtype)
}

const (
	Subtype = globals.Subtype("ldap")
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
