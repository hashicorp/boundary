// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package dbw

import (
	"context"
	"database/sql"
	"time"
)

// Writer interface defines create, update and retryable transaction handlers
type Writer interface {
	// DoTx will wrap the TxHandler in a retryable transaction
	DoTx(ctx context.Context, retryErrorsMatchingFn func(error) bool, retries uint, backOff Backoff, Handler TxHandler) (RetryInfo, error)

	// Update an object in the db, fieldMask is required and provides
	// field_mask.proto paths for fields that should be updated. The i interface
	// parameter is the type the caller wants to update in the db and its
	// fields are set to the update values. setToNullPaths is optional and
	// provides field_mask.proto paths for the fields that should be set to
	// null.  fieldMaskPaths and setToNullPaths must not intersect. The caller
	// is responsible for the transaction life cycle of the writer and if an
	// error is returned the caller must decide what to do with the transaction,
	// which almost always should be to rollback.  Update returns the number of
	// rows updated or an error.
	Update(ctx context.Context, i interface{}, fieldMaskPaths []string, setToNullPaths []string, opt ...Option) (int, error)

	// Create a resource in the database. The caller is responsible for the
	// transaction life cycle of the writer and if an error is returned the
	// caller must decide what to do with the transaction, which almost always
	// should be to rollback.
	Create(ctx context.Context, i interface{}, opt ...Option) error

	// CreateItems will create multiple items of the same type. The caller is
	// responsible for the transaction life cycle of the writer and if an error
	// is returned the caller must decide what to do with the transaction, which
	// almost always should be to rollback.
	// Supported options: WithBatchSize, WithDebug, WithBeforeWrite,
	// WithAfterWrite, WithReturnRowsAffected, OnConflict, WithVersion,
	// WithTable, and WithWhere.
	// WithLookup is not a supported option.
	CreateItems(ctx context.Context, createItems interface{}, opt ...Option) error

	// Delete a resource in the database. The caller is responsible for the
	// transaction life cycle of the writer and if an error is returned the
	// caller must decide what to do with the transaction, which almost always
	// should be to rollback. Delete returns the number of rows deleted or an
	// error.
	Delete(ctx context.Context, i interface{}, opt ...Option) (int, error)

	// DeleteItems will delete multiple items of the same type. The caller is
	// responsible for the transaction life cycle of the writer and if an error
	// is returned the caller must decide what to do with the transaction, which
	// almost always should be to rollback. Delete returns the number of rows
	// deleted or an error.
	DeleteItems(ctx context.Context, deleteItems interface{}, opt ...Option) (int, error)

	// Exec will execute the sql with the values as parameters. The int returned
	// is the number of rows affected by the sql. No options are currently
	// supported.
	Exec(ctx context.Context, sql string, values []interface{}, opt ...Option) (int, error)

	// Query will run the raw query and return the *sql.Rows results.  The
	// caller must close the returned *sql.Rows. Query can/should be used in
	// combination with ScanRows.  Query is included in the Writer interface
	// so callers can execute updates and inserts with returning values.
	Query(ctx context.Context, sql string, values []interface{}, opt ...Option) (*sql.Rows, error)

	// ScanRows will scan sql rows into the interface provided
	ScanRows(rows *sql.Rows, result interface{}) error

	// Begin will start a transaction.  NOTE: consider using DoTx(...) with a
	// TxHandler since it supports a better interface for managing transactions
	// via a TxHandler.
	Begin(ctx context.Context) (*RW, error)

	// Rollback will rollback the current transaction.  NOTE: consider using
	// DoTx(...) with a TxHandler since it supports a better interface for
	// managing transactions  via a TxHandler.
	Rollback(ctx context.Context) error

	// Commit will commit a transaction.  NOTE: consider using DoTx(...) with a
	// TxHandler since it supports a better interface for managing transactions
	// via a TxHandler.
	Commit(ctx context.Context) error

	// Dialect returns the dialect and raw connection name of the underlying database.
	Dialect() (_ DbType, rawName string, _ error)
}

// RetryInfo provides information on the retries of a transaction
type RetryInfo struct {
	Retries int
	Backoff time.Duration
}

// TxHandler defines a handler for a func that writes a transaction for use with DoTx
type TxHandler func(Reader, Writer) error
