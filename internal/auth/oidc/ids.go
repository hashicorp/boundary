package oidc

import (
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
)

const (
	AuthMethodPrefix = "amoidc"
	AccountPrefix    = "acctoidc"
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
