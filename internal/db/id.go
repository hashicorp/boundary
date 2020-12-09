package db

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/vault/sdk/helper/base62"
)

func NewPrivateId(prefix string) (string, error) {
	return newId(prefix)
}

// NewPublicId creates a new public id with the prefix
func NewPublicId(prefix string) (string, error) {
	return newId(prefix)
}

func newId(prefix string) (string, error) {
	const op = "db.newId"
	if prefix == "" {
		return "", errors.New(errors.InvalidParameter, op, "missing prefix")
	}
	publicId, err := base62.Random(10)
	if err != nil {
		return "", errors.Wrap(err, op, errors.WithMsg("unable to generate id"))
	}
	return fmt.Sprintf("%s_%s", prefix, publicId), nil
}
