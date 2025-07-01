// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package dbw

import (
	"context"
	"fmt"
)

// Begin will start a transaction
func (rw *RW) Begin(ctx context.Context) (*RW, error) {
	const op = "dbw.Begin"
	newTx := rw.underlying.wrapped.WithContext(ctx)
	newTx = newTx.Begin()
	if newTx.Error != nil {
		return nil, fmt.Errorf("%s: %w", op, newTx.Error)
	}
	return New(
		&DB{wrapped: newTx},
	), nil
}

// Rollback will rollback the current transaction
func (rw *RW) Rollback(ctx context.Context) error {
	const op = "dbw.Rollback"
	db := rw.underlying.wrapped.WithContext(ctx)
	if err := db.Rollback().Error; err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

// Commit will commit a transaction
func (rw *RW) Commit(ctx context.Context) error {
	const op = "dbw.Commit"
	db := rw.underlying.wrapped.WithContext(ctx)
	if err := db.Commit().Error; err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}
