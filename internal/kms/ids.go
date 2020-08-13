package kms

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
)

const (
	RootKeyPrefix        = "krk"
	RootKeyVersionPrefix = "krkv"
)

func newRootKeyId() (string, error) {
	id, err := db.NewPublicId(RootKeyPrefix)
	if err != nil {
		return "", fmt.Errorf("new root key id: %w", err)
	}
	return id, nil
}

func newRootKeyVersionId() (string, error) {
	id, err := db.NewPublicId(RootKeyVersionPrefix)
	if err != nil {
		return "", fmt.Errorf("new root key version id: %w", err)
	}
	return id, nil
}
