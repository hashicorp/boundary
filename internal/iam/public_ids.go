package iam

import (
	"fmt"

	"github.com/hashicorp/watchtower/internal/db"
)

const (
	RolePrefix = "r"
)

func newRoleId() (string, error) {
	publicId, err := db.NewPublicId(RolePrefix)
	if err != nil {
		return "", fmt.Errorf("new role id: %w", err)
	}
	return publicId, nil
}
