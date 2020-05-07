package db

import (
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/helper/base62"
)

// NewPublicId creates a new public id with the prefix
func NewPublicId(prefix string) (string, error) {
	if prefix == "" {
		return "", errors.New("error no prefix for new public id")
	}
	publicId, err := base62.Random(24)
	if err != nil {
		return "", fmt.Errorf("unable to generate public id: %w", err)
	}
	return fmt.Sprintf("%s_%s", prefix, publicId), nil
}
