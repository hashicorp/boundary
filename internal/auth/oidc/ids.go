package oidc

import (
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
)

const (
	AuthMethodPrefix = "amoidc"
)

func newAuthMethodId() (string, error) {
	const op = "oidc.newAuthMethodId"
	id, err := db.NewPublicId(AuthMethodPrefix)
	if err != nil {
		return "", errors.Wrap(err, op)
	}
	return id, nil
}
