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

func newAccountId() (string, error) {
	const op = "oidc.newAccountId"
	id, err := db.NewPublicId(AccountPrefix)
	if err != nil {
		return "", errors.Wrap(err, op)
	}
	return id, nil
}
