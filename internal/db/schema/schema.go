// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package schema

import (
	"context"

	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/errors"
)

// MigrateStore executes the migrations needed to initialize the store. It
// returns true if migrations actually ran; false if the database is already current
// or if there was an error.  Supports the WithEditions(...) option.
func MigrateStore(ctx context.Context, dialect Dialect, url string, opt ...Option) (bool, error) {
	const op = "schema.MigrateStore"

	d, err := common.SqlOpen(dialect.String(), url)
	if err != nil {
		return false, errors.Wrap(ctx, err, op)
	}

	sMan, err := NewManager(ctx, dialect, d, opt...)
	if err != nil {
		return false, errors.Wrap(ctx, err, op)
	}
	defer sMan.Close(ctx)

	st, err := sMan.CurrentState(ctx)
	if err != nil {
		return false, errors.Wrap(ctx, err, op)
	}

	if st.Initialized && st.MigrationsApplied() {
		return false, nil
	}

	if _, err := sMan.ApplyMigrations(ctx); err != nil {
		return false, errors.Wrap(ctx, err, op)
	}

	return true, nil
}
