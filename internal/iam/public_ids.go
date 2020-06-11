package iam

import (
	"fmt"

	"github.com/hashicorp/watchtower/internal/db"
)

const (
	UserPrefix  = "u"
	GroupPrefix = "g"
)

func newUserId() (string, error) {
	id, err := db.NewPublicId(UserPrefix)
	if err != nil {
		return "", fmt.Errorf("new user id: %w", err)
	}
	return id, nil
}

func newGroupId() (string, error) {
	id, err := db.NewPublicId(GroupPrefix)
	if err != nil {
		return "", fmt.Errorf("new group id: %w", err)
	}
	return id, nil
}
