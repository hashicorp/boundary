// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package db

import (
	"context"
	stderrors "errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/oplog/store"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/go-dbw"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

// RoTxHandler is a function that will be executed within a read-only transaction.
type RoTxHandler func(Reader) error

// RwTxHandler is a function that will be executed within a read-write transaction.
type RwTxHandler func(NewWriter) error

type txOptions struct {
	retries uint
	backOff Backoff
}

func getTxOptions(opts []TxOption) *txOptions {
	txOpts := txOptions{
		retries: StdRetryCnt,
		backOff: ExpBackoff{},
	}
	for _, opt := range opts {
		opt(&txOpts)
	}
	return &txOpts
}

// TxOption is used to configure the transaction.
type TxOption func(*txOptions)

// TransactionManager defines the interface for interacting with the database.
// All database operations require an explicit transaction with a defined backoff
// and retry mechanism.
type TransactionManager interface {
	// DoRoTx will start a read-only transaction and execute the handler. Retries
	// will be attempted based on the backoff strategy and number of retries.
	DoRoTx(ctx context.Context, handler RoTxHandler, opts ...TxOption) (RetryInfo, error)
	// DoRwTx will start a read-write transaction and execute the handler. Retries
	// will be attempted based on the backoff strategy and number of retries.
	DoRwTx(ctx context.Context, handler RwTxHandler, opts ...TxOption) (RetryInfo, error)

	// Writer returns a writer suitable for a single read-write operation.
	Writer() NewWriter
	// Reader returns a reader suitable for a single read-only operation.
	Reader() Reader
}

// NewWriter interface defines read/write operations for resources.
// TODO: Remove the old Writer interface and rename this Writer.
type NewWriter interface {
	Reader

	// Update an object in the db, fieldMask is required and provides
	// field_mask.proto paths for fields that should be updated. The i interface
	// parameter is the type the caller wants to update in the db and its
	// fields are set to the update values. setToNullPaths is optional and
	// provides field_mask.proto paths for the fields that should be set to
	// null.  fieldMaskPaths and setToNullPaths must not intersect. The caller
	// is responsible for the transaction life cycle of the writer and if an
	// error is returned the caller must decide what to do with the transaction,
	// which almost always should be to rollback.  Update returns the number of
	// rows updated or an error. Supported options: WithOplog.
	Update(ctx context.Context, i any, fieldMaskPaths []string, setToNullPaths []string, opt ...Option) (int, error)

	// Create an object in the db with options: WithDebug, WithOplog, NewOplogMsg,
	// WithLookup, WithReturnRowsAffected, OnConflict, WithVersion, and
	// WithWhere. The caller is responsible for the transaction life cycle of
	// the writer and if an error is returned the caller must decide what to do
	// with the transaction, which almost always should be to rollback.
	Create(ctx context.Context, i any, opt ...Option) error

	// CreateItems will create multiple items of the same type.
	// Supported options: WithDebug, WithOplog, WithOplogMsgs,
	// WithReturnRowsAffected, OnConflict, WithVersion, and WithWhere.
	/// WithOplog and WithOplogMsgs may not be used together. WithLookup is not
	// a supported option. The caller is responsible for the transaction life
	// cycle of the writer and if an error is returned the caller must decide
	// what to do with the transaction, which almost always should be to
	// rollback.
	CreateItems(ctx context.Context, createItems any, opt ...Option) error

	// Delete an object in the db with options: WithOplog, WithDebug.
	// The caller is responsible for the transaction life cycle of the writer
	// and if an error is returned the caller must decide what to do with
	// the transaction, which almost always should be to rollback. Delete
	// returns the number of rows deleted or an error.
	Delete(ctx context.Context, i any, opt ...Option) (int, error)

	// DeleteItems will delete multiple items of the same type.
	// Supported options: WithOplog and WithOplogMsgs. WithOplog and
	// WithOplogMsgs may not be used together. The caller is responsible for the
	// transaction life cycle of the writer and if an error is returned the
	// caller must decide what to do with the transaction, which almost always
	// should be to rollback. Delete returns the number of rows deleted or an error.
	DeleteItems(ctx context.Context, deleteItems any, opt ...Option) (int, error)

	// Exec will execute the sql with the values as parameters. The int returned
	// is the number of rows affected by the sql. No options are currently
	// supported.
	Exec(ctx context.Context, sql string, values []any, opt ...Option) (int, error)

	// GetTicket returns an oplog ticket for the aggregate root of "i" which can
	// be used to WriteOplogEntryWith for that aggregate root.
	GetTicket(ctx context.Context, i any) (*store.Ticket, error)

	// WriteOplogEntryWith will write an oplog entry with the msgs provided for
	// the ticket's aggregateName. No options are currently supported.
	WriteOplogEntryWith(
		ctx context.Context,
		wrapper wrapping.Wrapper,
		ticket *store.Ticket,
		metadata oplog.Metadata,
		msgs []*oplog.Message,
		opt ...Option,
	) error
}

type transactionManager struct {
	underlying *DB
}

// NewTransactionManager creates a new transaction manager.
func NewTransactionManager(db *DB) TransactionManager {
	return &transactionManager{
		underlying: db,
	}
}

func (t *transactionManager) DoRoTx(ctx context.Context, handler RoTxHandler, opts ...TxOption) (RetryInfo, error) {
	const op = "db.(*transactionManager).DoRoTx"
	txOpts := getTxOptions(opts)
	switch {
	case util.IsNil(t.underlying):
		return RetryInfo{}, errors.New(ctx, errors.InvalidParameter, op, "missing db")
	case util.IsNil(t.underlying):
		return RetryInfo{}, errors.New(ctx, errors.InvalidParameter, op, "missing underlying db")
	case util.IsNil(txOpts.backOff):
		return RetryInfo{}, errors.New(ctx, errors.InvalidParameter, op, "missing backoff")
	case util.IsNil(handler):
		return RetryInfo{}, errors.New(ctx, errors.InvalidParameter, op, "missing handler")
	}
	info := RetryInfo{}
	for attempts := uint(1); ; attempts++ {
		if attempts > txOpts.retries+1 {
			return info, errors.New(ctx, errors.MaxRetries, op, fmt.Sprintf("Too many retries: %d of %d", attempts-1, txOpts.retries+1), errors.WithoutEvent())
		}

		beginTx, err := dbw.New(t.underlying.wrapped.Load()).Begin(ctx)
		if err != nil {
			return info, wrapError(ctx, err, op)
		}

		// TODO: In the future, if we want to support read-only replicas,
		// this would create a new transaction to (one of?) the read-only
		// replica(s).
		newTxDb := &DB{wrapped: new(atomic.Pointer[dbw.DB])}
		newTxDb.wrapped.Store(beginTx.DB())
		newRW := New(newTxDb)

		if err := handler(newRW); err != nil {
			if err := beginTx.Rollback(ctx); err != nil {
				return info, wrapError(ctx, err, op)
			}
			if errors.Match(errors.T(errors.TicketAlreadyRedeemed), err) {
				d := txOpts.backOff.Duration(attempts)
				info.Retries++
				info.Backoff = info.Backoff + d
				time.Sleep(d)
				continue
			}
			return info, errors.Wrap(ctx, err, op, errors.WithoutEvent())
		}

		var txnErr error
		if commitErr := beginTx.Commit(ctx); commitErr != nil {
			txnErr = stderrors.Join(txnErr, errors.Wrap(ctx, commitErr, op, errors.WithMsg("commit error")))
			if err := beginTx.Rollback(ctx); err != nil {
				return info, stderrors.Join(txnErr, errors.Wrap(ctx, err, op, errors.WithMsg("rollback error")))
			}
			return info, txnErr
		}
		return info, nil
	}
}

func (t *transactionManager) DoRwTx(ctx context.Context, handler RwTxHandler, opts ...TxOption) (RetryInfo, error) {
	const op = "db.(*transactionManager).DoRwTx"
	txOpts := getTxOptions(opts)
	switch {
	case util.IsNil(t.underlying):
		return RetryInfo{}, errors.New(ctx, errors.InvalidParameter, op, "missing db")
	case util.IsNil(t.underlying):
		return RetryInfo{}, errors.New(ctx, errors.InvalidParameter, op, "missing underlying db")
	case util.IsNil(txOpts.backOff):
		return RetryInfo{}, errors.New(ctx, errors.InvalidParameter, op, "missing backoff")
	case util.IsNil(handler):
		return RetryInfo{}, errors.New(ctx, errors.InvalidParameter, op, "missing handler")
	}
	info := RetryInfo{}
	for attempts := uint(1); ; attempts++ {
		if attempts > txOpts.retries+1 {
			return info, errors.New(ctx, errors.MaxRetries, op, fmt.Sprintf("Too many retries: %d of %d", attempts-1, txOpts.retries+1), errors.WithoutEvent())
		}

		beginTx, err := dbw.New(t.underlying.wrapped.Load()).Begin(ctx)
		if err != nil {
			return info, wrapError(ctx, err, op)
		}

		// TODO: In the future, if we want to support read-only replicas,
		// this would create a new transaction to the primary DB (not a replica)
		newTxDb := &DB{wrapped: new(atomic.Pointer[dbw.DB])}
		newTxDb.wrapped.Store(beginTx.DB())
		newRW := New(newTxDb)

		if err := handler(newRW); err != nil {
			if err := beginTx.Rollback(ctx); err != nil {
				return info, wrapError(ctx, err, op)
			}
			if errors.Match(errors.T(errors.TicketAlreadyRedeemed), err) {
				d := txOpts.backOff.Duration(attempts)
				info.Retries++
				info.Backoff = info.Backoff + d
				time.Sleep(d)
				continue
			}
			return info, errors.Wrap(ctx, err, op, errors.WithoutEvent())
		}

		var txnErr error
		if commitErr := beginTx.Commit(ctx); commitErr != nil {
			txnErr = stderrors.Join(txnErr, errors.Wrap(ctx, commitErr, op, errors.WithMsg("commit error")))
			if err := beginTx.Rollback(ctx); err != nil {
				return info, stderrors.Join(txnErr, errors.Wrap(ctx, err, op, errors.WithMsg("rollback error")))
			}
			return info, txnErr
		}
		return info, nil
	}
}

func (t *transactionManager) Writer() NewWriter {
	// TODO: In the future, if we want to support read-only replicas,
	// this would use the primary DB (not a replica)
	return New(t.underlying)
}

func (t *transactionManager) Reader() Reader {
	// TODO: In the future, if we want to support read-only replicas,
	// this would use (one of?) the read-only replica(s).
	return New(t.underlying)
}
