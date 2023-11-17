// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
)

func withOptError(ctx context.Context) Option {
	return func(o *options) error {
		return errors.New(ctx, errors.Unknown, "withOptErrors", "with opt error")
	}
}

func TestAppToken(t *testing.T, conn *db.DB, scopeId, createBy string, grants []string) {
	t.Helper()
	panic("todo - finish creating an app token with the specified grants")
}
