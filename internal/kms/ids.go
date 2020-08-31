package kms

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
)

const (
	RootKeyPrefix            = "krk"
	RootKeyVersionPrefix     = "krkv"
	DatabaseKeyPrefix        = "kdk"
	DatabaseKeyVersionPrefix = "kdkv"
	OplogKeyPrefix           = "kopk"
	OplogKeyVersionPrefix    = "kopkv"
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

func newDatabaseKeyId() (string, error) {
	id, err := db.NewPublicId(DatabaseKeyPrefix)
	if err != nil {
		return "", fmt.Errorf("new database key id: %w", err)
	}
	return id, nil
}

func newDatabaseKeyVersionId() (string, error) {
	id, err := db.NewPublicId(DatabaseKeyVersionPrefix)
	if err != nil {
		return "", fmt.Errorf("new database key version id: %w", err)
	}
	return id, nil
}

func newOplogKeyId() (string, error) {
	id, err := db.NewPublicId(OplogKeyPrefix)
	if err != nil {
		return "", fmt.Errorf("new oplog key id: %w", err)
	}
	return id, nil
}

func newOplogKeyVersionId() (string, error) {
	id, err := db.NewPublicId(OplogKeyVersionPrefix)
	if err != nil {
		return "", fmt.Errorf("new oplog key version id: %w", err)
	}
	return id, nil
}
