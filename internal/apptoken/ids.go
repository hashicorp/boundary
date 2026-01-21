// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
)

func newAppTokenId(ctx context.Context) (string, error) {
	const op = "apptoken.newAppTokenId"
	id, err := db.NewPublicId(ctx, globals.AppTokenPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	return id, nil
}

func newAppTokenPermissionId(ctx context.Context) (string, error) {
	const op = "apptoken.newAppTokenPermissionId"
	id, err := db.NewPublicId(ctx, globals.AppTokenPermissionPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	return id, nil
}
