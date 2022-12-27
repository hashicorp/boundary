package ldap

import (
	"context"

	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/subtypes"
)

func init() {
	if err := subtypes.Register(auth.Domain, Subtype, AuthMethodPrefix, AccountPrefix); err != nil {
		panic(err)
	}
}

const (
	// AuthMethodPrefix defines the prefix for AuthMethod public ids.
	AuthMethodPrefix = "amldap"
	// AccountPrefix defines the prefix for Account public ids.
	AccountPrefix = "acctldap"

	Subtype = subtypes.Subtype("ldap")
)

func newAuthMethodId(ctx context.Context) (string, error) {
	const op = "ldap.newAuthMethodId"
	id, err := db.NewPublicId(AuthMethodPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	return id, nil
}

func newAccountId(ctx context.Context, authMethodId, loginName string) (string, error) {
	const op = "ldap.newAccountId"
	// there's a unique index on: auth method id + login name
	id, err := db.NewPublicId(AccountPrefix, db.WithPrngValues([]string{authMethodId, loginName}))
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	return id, nil
}
