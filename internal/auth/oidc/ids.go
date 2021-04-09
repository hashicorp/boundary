package oidc

import (
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
)

const (
	// AuthMethodPrefix defines the prefix for AuthMethod public ids.
	AuthMethodPrefix = "amoidc"
	// AccountPrefix defines the prefix for Account public ids.
	AccountPrefix = "acctoidc"
)

func newAuthMethodId() (string, error) {
	const op = "oidc.newAuthMethodId"
	id, err := db.NewPublicId(AuthMethodPrefix)
	if err != nil {
		return "", errors.Wrap(err, op)
	}
	return id, nil
}

func newAccountId(authMethodId, issuer, sub string) (string, error) {
	const op = "oidc.newAccountId"
	if authMethodId == "" {
		return "", errors.New(errors.InvalidParameter, op, "missing auth method id")
	}
	if issuer == "" {
		return "", errors.New(errors.InvalidParameter, op, "missing issuer")
	}
	if sub == "" {
		return "", errors.New(errors.InvalidParameter, op, "missing subject")
	}
	id, err := db.NewPublicId(AccountPrefix, db.WithPrngValues([]string{authMethodId, issuer, sub}))
	if err != nil {
		return "", errors.Wrap(err, op)
	}
	return id, nil
}
