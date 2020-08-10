package iam

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/types/scope"
)

const (
	UserPrefix      = "u"
	GroupPrefix     = "g"
	RolePrefix      = "r"
	RoleGrantPrefix = "rg"
)

func newRoleId() (string, error) {
	id, err := db.NewPublicId(RolePrefix)
	if err != nil {
		return "", fmt.Errorf("new role id: %w", err)
	}
	return id, nil
}

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

func newScopeId(scopeType scope.Type) (string, error) {
	if scopeType == scope.Unknown {
		return "", fmt.Errorf("new scope id: unknown is not supported %w", db.ErrInvalidParameter)
	}
	id, err := db.NewPublicId(scopeType.Prefix())
	if err != nil {
		return "", fmt.Errorf("new %s id: %w", scopeType.String(), err)
	}
	return id, nil
}
