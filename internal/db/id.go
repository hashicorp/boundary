package db

import (
	"fmt"

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
	if prefix == "" {
		return "", fmt.Errorf("missing prefix %w", ErrInvalidParameter)
	}
	publicId, err := base62.Random(10)
	if err != nil {
		return "", fmt.Errorf("unable to generate id: %w", err)
	}
	return fmt.Sprintf("%s_%s", prefix, publicId), nil
}
