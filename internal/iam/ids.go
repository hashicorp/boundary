// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/scope"
)

const (
	// RoleGrantPrefix is the prefix for role grants
	RoleGrantPrefix = "rg"
)

func newRoleId(ctx context.Context) (string, error) {
	id, err := db.NewPublicId(ctx, globals.RolePrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, "iam.newRoleId")
	}
	return id, nil
}

func newUserId(ctx context.Context) (string, error) {
	id, err := db.NewPublicId(ctx, globals.UserPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, "iam.newUserId")
	}
	return id, nil
}

func newGroupId(ctx context.Context) (string, error) {
	id, err := db.NewPublicId(ctx, globals.GroupPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, "iam.newGroupId")
	}
	return id, nil
}

func newScopeId(ctx context.Context, scopeType scope.Type) (string, error) {
	const op = "iam.newScopeId"
	if scopeType == scope.Unknown {
		return "", errors.New(ctx, errors.InvalidParameter, op, "unknown scope is not supported")
	}
	id, err := db.NewPublicId(ctx, scopeType.Prefix())
	if err != nil {
		return "", errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("scope type: %s", scopeType.String())))
	}
	return id, nil
}
