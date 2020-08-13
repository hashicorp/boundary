package kms

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
)

const (
	ExternalConfigPrefix = "kec"
)

func newExternalConfigId() (string, error) {
	id, err := db.NewPublicId(ExternalConfigPrefix)
	if err != nil {
		return "", fmt.Errorf("new external config id: %w", err)
	}
	return id, nil
}
