// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package db

import (
	"context"
	"database/sql"
	stderrors "errors"
	"fmt"
	"reflect"
	"sync/atomic"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/oplog/store"
	"github.com/hashicorp/go-dbw"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

const (
	NoRowsAffected = 0

	// DefaultLimit is the default for results for boundary
	DefaultLimit = 10000
)

// OrderBy defines an enum type for declaring a column's order by criteria.
type OrderBy int

const (
	// UnknownOrderBy would designate an unknown ordering of the column, which
	// is the standard ordering for any select without an order by clause.
	UnknownOrderBy = iota

	// AscendingOrderBy would designate ordering the column in ascending order.
	AscendingOrderBy

	// DescendingOrderBy would designate ordering the column in decending order.
	DescendingOrderBy
)

// TxHandler defines a handler for a func that writes a transaction for use with DoTx
type TxHandler func(Reader, Writer) error

// Reader interface defines lookups/searching for resources. It does
// not allow for writing to the db.
type Reader interface {
	// LookupById will lookup a resource by its primary key id, which must be
	// unique. If the resource implements either ResourcePublicIder or
	// ResourcePrivateIder interface, then they are used as the resource's
	// primary key for lookup.  Otherwise, the resource tags are used to
	// determine it's primary key(s) for lookup.
	LookupById(ctx context.Context, resource any, opt ...Option) error

	// LookupByPublicId will lookup resource by its public_id which must be unique.
	LookupByPublicId(ctx context.Context, resource ResourcePublicIder, opt ...Option) error

	// LookupWhere will lookup and return the first resource using a where clause with parameters
	LookupWhere(ctx context.Context, resource any, where string, args []any, opt ...Option) error

	// SearchWhere will search for all the resources it can find using a where
	// clause with parameters. Supports the WithLimit option.  If
	// WithLimit < 0, then unlimited results are returned.  If WithLimit == 0, then
	// default limits are used for results.
	SearchWhere(ctx context.Context, resources any, where string, args []any, opt ...Option) error

	// Query will run the raw query and return the *sql.Rows results. Query will
	// operate within the context of any ongoing transaction for the db.Reader.  The
	// caller must close the returned *sql.Rows. Query can/should be used in
	// combination with ScanRows.
	Query(ctx context.Context, sql string, values []any, opt ...Option) (*sql.Rows, error)

	// ScanRows will scan sql rows into the interface provided
	ScanRows(ctx context.Context, rows *sql.Rows, result any) error

	// Now returns the current transaction timestamp. Now will return the same
	// timestamp whenever it is called within a transaction. In other words, calling
	// Now at the start and at the end of a transaction will return the same value.
	Now(ctx context.Context) (time.Time, error)
}

// Writer interface defines create, update and retryable transaction handlers
type Writer interface {
	// DoTx will wrap the TxHandler in a retryable transaction
	DoTx(ctx context.Context, retries uint, backOff Backoff, Handler TxHandler) (RetryInfo, error)

	// IsTx returns true if there's an existing transaction in progress
	IsTx(ctx context.Context) bool

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

	// Query will run the raw query and return the *sql.Rows results. Query will
	// operate within the context of any ongoing transaction for the db.Writer.  The
	// caller must close the returned *sql.Rows. Query can/should be used in
	// combination with ScanRows.  Query is included in the Writer interface
	// so callers can execute updates and inserts with returning values.
	Query(ctx context.Context, sql string, values []any, opt ...Option) (*sql.Rows, error)

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

	// ScanRows will scan sql rows into the interface provided
	ScanRows(ctx context.Context, rows *sql.Rows, result any) error
}

const (
	StdRetryCnt = 20
)

// RetryInfo provides information on the retries of a transaction
type RetryInfo struct {
	Retries int
	Backoff time.Duration
}

// ResourcePublicIder defines an interface that LookupByPublicId() can use to
// get the resource's public id.
type ResourcePublicIder interface {
	GetPublicId() string
}

// ResourcePrivateIder defines an interface that LookupById() can use to get the
// resource's private id.
type ResourcePrivateIder interface {
	GetPrivateId() string
}

type OpType int

const (
	UnknownOp     OpType = 0
	CreateOp      OpType = 1
	UpdateOp      OpType = 2
	DeleteOp      OpType = 3
	CreateItemsOp OpType = 4
	DeleteItemsOp OpType = 5
	LookupOp      OpType = 6
	SearchOp      OpType = 7
)

// VetForWriter provides an interface that Create and Update can use to vet the
// resource before before writing it to the db.  For optType == UpdateOp,
// options WithFieldMaskPath and WithNullPaths are supported.  For optType ==
// CreateOp, no options are supported
type VetForWriter interface {
	VetForWrite(ctx context.Context, r Reader, opType OpType, opt ...Option) error
}

// Db uses a gorm DB connection for read/write
type Db struct {
	underlying *DB
}

// ensure that Db implements the interfaces of: Reader and Writer
var (
	_ Reader = (*Db)(nil)
	_ Writer = (*Db)(nil)
)

func New(underlying *DB) *Db {
	return &Db{underlying: underlying}
}

// UnderlyingDB returns a function to get the underlying *dbw.DB. The function
// should be called every time rather than caching the value, as the value may
// change from call to call.
func (rw *Db) UnderlyingDB() func() *dbw.DB {
	return func() *dbw.DB {
		return rw.underlying.wrapped.Load()
	}
}

// Exec will execute the sql with the values as parameters. The int returned
// is the number of rows affected by the sql. WithDebug is supported.
func (rw *Db) Exec(ctx context.Context, sql string, values []any, opt ...Option) (int, error) {
	const op = "db.Exec"
	if sql == "" {
		return NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing sql")
	}
	opts := GetOpts(opt...)
	rowsAffected, err := dbw.New(rw.underlying.wrapped.Load()).Exec(ctx, sql, values, dbw.WithDebug(opts.withDebug))
	if err != nil {
		return NoRowsAffected, wrapError(ctx, err, op)
	}
	return rowsAffected, nil
}

// Query will run the raw query and return the *sql.Rows results. Query will
// operate within the context of any ongoing transaction for the db.Reader.  The
// caller must close the returned *sql.Rows. Query can/should be used in
// combination with ScanRows.
func (rw *Db) Query(ctx context.Context, sql string, values []any, opt ...Option) (*sql.Rows, error) {
	const op = "db.Query"
	if sql == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing sql")
	}
	opts := GetOpts(opt...)
	rows, err := dbw.New(rw.underlying.wrapped.Load()).Query(ctx, sql, values, dbw.WithDebug(opts.withDebug))
	if err != nil {
		return nil, wrapError(ctx, err, op)
	}
	return rows, nil
}

// Scan rows will scan the rows into the interface
func (rw *Db) ScanRows(ctx context.Context, rows *sql.Rows, result any) error {
	const op = "db.ScanRows"
	if rw.underlying == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing underlying db")
	}
	if isNil(result) {
		return errors.New(ctx, errors.InvalidParameter, op, "missing result")
	}
	if err := dbw.New(rw.underlying.wrapped.Load()).ScanRows(rows, result); err != nil {
		return wrapError(ctx, err, op)
	}
	return nil
}

// Create an object in the db with options: WithDebug, WithOplog, NewOplogMsg,
// WithLookup, WithReturnRowsAffected, OnConflict, WithVersion, and WithWhere.
//
// WithOplog will write an oplog entry for the create. NewOplogMsg will return
// in-memory oplog message.  WithOplog and NewOplogMsg cannot be used together.
// WithLookup with to force a lookup after create.
//
// OnConflict specifies alternative actions to take when an insert results in a
// unique constraint or exclusion constraint error. If WithVersion is used, then
// the update for on conflict will include the version number, which basically
// makes the update use optimistic locking and the update will only succeed if
// the existing rows version matches the WithVersion option.  Zero is not a
// valid value for the WithVersion option and will return an error. WithWhere
// allows specifying an additional constraint on the on conflict operation in
// addition to the on conflict target policy (columns or constraint).
func (rw *Db) Create(ctx context.Context, i any, opt ...Option) error {
	const op = "db.Create"
	if rw.underlying == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing underlying db")
	}
	dbwOpts, err := getDbwOptions(ctx, rw, i, CreateOp, opt...)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if err := dbw.New(rw.underlying.wrapped.Load()).Create(ctx, i, dbwOpts...); err != nil {
		return wrapError(ctx, err, op)
	}
	return nil
}

// CreateItems will create multiple items of the same type. Supported options:
// WithDebug, WithOplog, WithOplogMsgs, WithReturnRowsAffected, OnConflict,
// WithVersion, and WithWhere  WithOplog and WithOplogMsgs may not be used
// together.  WithLookup is not a supported option.
func (rw *Db) CreateItems(ctx context.Context, createItems any, opt ...Option) error {
	const op = "db.CreateItems"
	if rw.underlying == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing underlying db")
	}
	dbwOpts, err := getDbwOptions(ctx, rw, createItems, CreateItemsOp, opt...)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if err := dbw.New(rw.underlying.wrapped.Load()).CreateItems(ctx, createItems, dbwOpts...); err != nil {
		return wrapError(ctx, err, op)
	}
	return nil
}

// Update an object in the db, fieldMask is required and provides
// field_mask.proto paths for fields that should be updated. The i interface
// parameter is the type the caller wants to update in the db and its fields are
// set to the update values. setToNullPaths is optional and provides
// field_mask.proto paths for the fields that should be set to null.
// fieldMaskPaths and setToNullPaths must not intersect. The caller is
// responsible for the transaction life cycle of the writer and if an error is
// returned the caller must decide what to do with the transaction, which almost
// always should be to rollback.  Update returns the number of rows updated.
//
// Supported options: WithOplog, NewOplogMsg, WithWhere, WithDebug, and
// WithVersion. WithOplog will write an oplog entry for the update. NewOplogMsg
// will return in-memory oplog message. WithOplog and NewOplogMsg cannot be used
// together. If WithVersion is used, then the update will include the version
// number in the update where clause, which basically makes the update use
// optimistic locking and the update will only succeed if the existing rows
// version matches the WithVersion option. Zero is not a valid value for the
// WithVersion option and will return an error. WithWhere allows specifying an
// additional constraint on the operation in addition to the PKs. WithDebug will
// turn on debugging for the update call.
func (rw *Db) Update(ctx context.Context, i any, fieldMaskPaths []string, setToNullPaths []string, opt ...Option) (int, error) {
	const op = "db.Update"
	if rw.underlying == nil {
		return NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing underlying db")
	}
	optCp := make([]Option, 0, len(opt)+2)
	optCp = append(optCp, opt...)
	optCp = append(optCp, WithFieldMaskPaths(fieldMaskPaths), WithNullPaths(setToNullPaths))
	dbwOpts, err := getDbwOptions(ctx, rw, i, UpdateOp, optCp...)
	if err != nil {
		return NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	rowsUpdated, err := dbw.New(rw.underlying.wrapped.Load()).Update(ctx, i, fieldMaskPaths, setToNullPaths, dbwOpts...)
	if err != nil {
		return NoRowsAffected, wrapError(ctx, err, op)
	}
	return rowsUpdated, nil
}

// Delete an object in the db with options: WithOplog, NewOplogMsg, WithWhere.
// WithOplog will write an oplog entry for the delete. NewOplogMsg will return
// in-memory oplog message. WithOplog and NewOplogMsg cannot be used together.
// WithWhere allows specifying an additional constraint on the operation in
// addition to the PKs. Delete returns the number of rows deleted and any errors.
func (rw *Db) Delete(ctx context.Context, i any, opt ...Option) (int, error) {
	const op = "db.Delete"
	if rw.underlying == nil {
		return NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing underlying db")
	}
	dbwOpts, err := getDbwOptions(ctx, rw, i, DeleteOp, opt...)
	if err != nil {
		return NoRowsAffected, wrapError(ctx, err, op)
	}
	rowsUpdated, err := dbw.New(rw.underlying.wrapped.Load()).Delete(ctx, i, dbwOpts...)
	if err != nil {
		return NoRowsAffected, wrapError(ctx, err, op)
	}
	return rowsUpdated, nil
}

// DeleteItems will delete multiple items of the same type. Supported options:
// WithOplog and WithOplogMsgs.  WithOplog and WithOplogMsgs may not be used
// together.
func (rw *Db) DeleteItems(ctx context.Context, deleteItems any, opt ...Option) (int, error) {
	const op = "db.DeleteItems"
	if rw.underlying == nil {
		return NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing underlying db")
	}
	dbwOpts, err := getDbwOptions(ctx, rw, deleteItems, DeleteItemsOp, opt...)
	if err != nil {
		return NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	rowsDeleted, err := dbw.New(rw.underlying.wrapped.Load()).DeleteItems(ctx, deleteItems, dbwOpts...)
	if err != nil {
		return NoRowsAffected, wrapError(ctx, err, op)
	}
	return rowsDeleted, nil
}

// DoTx will wrap the Handler func passed within a transaction with retries
// you should ensure that any objects written to the db in your TxHandler are retryable, which
// means that the object may be sent to the db several times (retried), so things like the primary key must
// be reset before retry
func (rw *Db) DoTx(ctx context.Context, retries uint, backOff Backoff, handler TxHandler) (RetryInfo, error) {
	const op = "db.DoTx"
	if rw.underlying == nil {
		return RetryInfo{}, errors.New(ctx, errors.InvalidParameter, op, "missing underlying db")
	}
	if backOff == nil {
		return RetryInfo{}, errors.New(ctx, errors.InvalidParameter, op, "missing backoff")
	}
	if handler == nil {
		return RetryInfo{}, errors.New(ctx, errors.InvalidParameter, op, "missing handler")
	}
	info := RetryInfo{}
	for attempts := uint(1); ; attempts++ {
		if attempts > retries+1 {
			return info, errors.New(ctx, errors.MaxRetries, op, fmt.Sprintf("Too many retries: %d of %d", attempts-1, retries+1), errors.WithoutEvent())
		}

		// step one of this, start a transaction...
		beginTx, err := dbw.New(rw.underlying.wrapped.Load()).Begin(ctx)
		if err != nil {
			return info, wrapError(ctx, err, op)
		}

		newTxDb := &DB{wrapped: new(atomic.Pointer[dbw.DB])}
		newTxDb.wrapped.Store(beginTx.DB())
		newRW := New(newTxDb)

		if err := handler(newRW, newRW); err != nil {
			if err := beginTx.Rollback(ctx); err != nil {
				return info, wrapError(ctx, err, op)
			}
			if errors.Match(errors.T(errors.TicketAlreadyRedeemed), err) {
				d := backOff.Duration(attempts)
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
			// unsure if rolling back is required or possible, but including
			// this attempt to rollback on a commit error just in case it's
			// possible.
			if err := beginTx.Rollback(ctx); err != nil {
				return info, stderrors.Join(txnErr, errors.Wrap(ctx, err, op, errors.WithMsg("rollback error")))
			}
			return info, txnErr
		}
		return info, nil // it all worked!!!
	}
}

// IsTx returns true if there's an existing transaction in progress
func (rw *Db) IsTx(_ context.Context) bool {
	return dbw.New(rw.underlying.wrapped.Load()).IsTx()
}

// LookupByPublicId will lookup resource by its public_id or private_id, which
// must be unique. WithTable and WithDebug are the only valid options, all other
// options are ignored.
func (rw *Db) LookupById(ctx context.Context, resourceWithIder any, opt ...Option) error {
	const op = "db.LookupById"
	if rw.underlying == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing underlying db")
	}
	opts := GetOpts(opt...)
	if err := dbw.New(rw.underlying.wrapped.Load()).LookupBy(ctx, resourceWithIder, dbw.WithDebug(opts.withDebug), dbw.WithTable(opts.withTable)); err != nil {
		var errOpts []errors.Option
		if errors.Is(err, dbw.ErrRecordNotFound) {
			// Not found is a common workflow in the application layer during lookup, suppress
			// the event here and allow the caller to log event if needed.
			errOpts = append(errOpts, errors.WithoutEvent())
		}
		return wrapError(ctx, err, op, errOpts...)
	}
	return nil
}

// LookupByPublicId will lookup resource by its public_id, which must be unique.
// WithTable and WithDebug are supported.
func (rw *Db) LookupByPublicId(ctx context.Context, resource ResourcePublicIder, opt ...Option) error {
	return rw.LookupById(ctx, resource, opt...)
}

// LookupWhere will lookup the first resource using a where clause with
// parameters (it only returns the first one). WithTable and WithDebug are
// supported.
func (rw *Db) LookupWhere(ctx context.Context, resource any, where string, args []any, opt ...Option) error {
	const op = "db.LookupWhere"
	if rw.underlying == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing underlying db")
	}
	opts := GetOpts(opt...)
	if err := dbw.New(rw.underlying.wrapped.Load()).LookupWhere(ctx, resource, where, args, dbw.WithDebug(opts.withDebug), dbw.WithTable(opts.withTable)); err != nil {
		var errOpts []errors.Option
		if errors.Is(err, dbw.ErrRecordNotFound) {
			// Not found is a common workflow in the application layer during lookup, suppress
			// the event here and allow the caller to log event if needed.
			errOpts = append(errOpts, errors.WithoutEvent())
		}
		return wrapError(ctx, err, op, errOpts...)
	}
	return nil
}

// SearchWhere will search for all the resources it can find using a where
// clause with parameters. An error will be returned if args are provided without a
// where clause.
//
// Supports the WithLimit option.  If WithLimit < 0, then unlimited results are returned.
// If WithLimit == 0, then default limits are used for results.
// Supports the WithOrder and WithDebug options.
func (rw *Db) SearchWhere(ctx context.Context, resources any, where string, args []any, opt ...Option) error {
	const op = "db.SearchWhere"
	if rw.underlying == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing underlying db")
	}
	dbwOpts, err := getDbwOptions(ctx, rw, resources, SearchOp, opt...)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if err := dbw.New(rw.underlying.wrapped.Load()).SearchWhere(ctx, resources, where, args, dbwOpts...); err != nil {
		return wrapError(ctx, err, op)
	}
	return nil
}

// Now returns the current transaction timestamp. Now will return the same
// timestamp whenever it is called within a transaction. In other words, calling
// Now at the start and at the end of a transaction will return the same value.
func (rw *Db) Now(ctx context.Context) (time.Time, error) {
	const op = "db.(*Db).Now"
	// The Postgres docs define the different pre-defined time variables available:
	// https://www.postgresql.org/docs/current/functions-datetime.html#FUNCTIONS-DATETIME-CURRENT.
	// The value produced by this function is equivalent to current_timestamp.
	rows, err := rw.Query(ctx, "select now()", nil)
	if err != nil {
		return time.Time{}, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query current timestamp"))
	}
	var now time.Time
	for rows.Next() {
		if err := rw.ScanRows(ctx, rows, &now); err != nil {
			return time.Time{}, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query current timestamp"))
		}
	}
	if err := rows.Err(); err != nil {
		return time.Time{}, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query current timestamp"))
	}
	return now, nil
}

func isNil(i any) bool {
	if i == nil {
		return true
	}
	switch reflect.TypeOf(i).Kind() {
	case reflect.Ptr, reflect.Map, reflect.Array, reflect.Chan, reflect.Slice:
		return reflect.ValueOf(i).IsNil()
	}
	return false
}

func wrapError(ctx context.Context, err error, op string, errOpts ...errors.Option) error {
	// See github.com/hashicorp/go-dbw/error.go for appropriate errors to test
	// for and wrap
	switch {
	case errors.Is(err, dbw.ErrInvalidParameter):
		errOpts = append(errOpts, errors.WithCode(errors.InvalidParameter))
	case errors.Is(err, dbw.ErrInternal):
		errOpts = append(errOpts, errors.WithCode(errors.Internal))
	case errors.Is(err, dbw.ErrRecordNotFound):
		errOpts = append(errOpts, errors.WithCode(errors.RecordNotFound))
	case errors.Is(err, dbw.ErrMaxRetries):
		errOpts = append(errOpts, errors.WithCode(errors.MaxRetries))
	case errors.Is(err, dbw.ErrInvalidFieldMask):
		errOpts = append(errOpts, errors.WithCode(errors.InvalidFieldMask))
	}

	return errors.Wrap(ctx, err, errors.Op(op), append(errOpts, errors.WithoutEvent())...)
}
