// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package db

import (
	"context"
	"database/sql"

	"github.com/hashicorp/go-dbw"
)

var (
	_ dbw.Reader = (*changeSafeDbwReader)(nil)
	_ dbw.Writer = (*changeSafeDbwWriter)(nil)
)

// changeSafeDbwReader is a type that wraps a *db.Db as a dbw.Reader and ensures
// that uses of the underlying database follows changes to the connection.
type changeSafeDbwReader struct {
	db *Db
}

func NewChangeSafeDbwReader(underlying *Db) dbw.Reader {
	return &changeSafeDbwReader{db: underlying}
}

func (r *changeSafeDbwReader) LookupBy(ctx context.Context, resource any, opt ...dbw.Option) error {
	return dbw.New(r.db.underlying.wrapped.Load()).LookupBy(ctx, resource, opt...)
}

func (r *changeSafeDbwReader) LookupByPublicId(ctx context.Context, resource dbw.ResourcePublicIder, opt ...dbw.Option) error {
	return dbw.New(r.db.underlying.wrapped.Load()).LookupByPublicId(ctx, resource, opt...)
}

func (r *changeSafeDbwReader) LookupWhere(ctx context.Context, resource any, where string, args []any, opt ...dbw.Option) error {
	return dbw.New(r.db.underlying.wrapped.Load()).LookupWhere(ctx, resource, where, args, opt...)
}

func (r *changeSafeDbwReader) Query(ctx context.Context, sql string, values []any, opt ...dbw.Option) (*sql.Rows, error) {
	return dbw.New(r.db.underlying.wrapped.Load()).Query(ctx, sql, values, opt...)
}

func (r *changeSafeDbwReader) ScanRows(rows *sql.Rows, result any) error {
	return dbw.New(r.db.underlying.wrapped.Load()).ScanRows(rows, result)
}

func (r *changeSafeDbwReader) SearchWhere(ctx context.Context, resources any, where string, args []any, opt ...dbw.Option) error {
	return dbw.New(r.db.underlying.wrapped.Load()).SearchWhere(ctx, resources, where, args, opt...)
}

func (r *changeSafeDbwReader) Dialect() (_ dbw.DbType, rawName string, _ error) {
	return r.db.underlying.wrapped.Load().DbType()
}

// changeSafeDbwWriter is a type that wraps a *db.Db as a dbw.Writer and ensures
// that uses of the underlying database follows changes to the connection.
type changeSafeDbwWriter struct {
	db *Db
}

func NewChangeSafeDbwWriter(underlying *Db) dbw.Writer {
	return &changeSafeDbwWriter{db: underlying}
}

func (w *changeSafeDbwWriter) Begin(ctx context.Context) (*dbw.RW, error) {
	return dbw.New(w.db.underlying.wrapped.Load()).Begin(ctx)
}

func (w *changeSafeDbwWriter) Commit(ctx context.Context) error {
	return dbw.New(w.db.underlying.wrapped.Load()).Commit(ctx)
}

func (w *changeSafeDbwWriter) Create(ctx context.Context, i any, opt ...dbw.Option) error {
	return dbw.New(w.db.underlying.wrapped.Load()).Create(ctx, i, opt...)
}

func (w *changeSafeDbwWriter) CreateItems(ctx context.Context, createItems any, opt ...dbw.Option) error {
	return dbw.New(w.db.underlying.wrapped.Load()).CreateItems(ctx, createItems, opt...)
}

func (w *changeSafeDbwWriter) Delete(ctx context.Context, i any, opt ...dbw.Option) (int, error) {
	return dbw.New(w.db.underlying.wrapped.Load()).Delete(ctx, i, opt...)
}

func (w *changeSafeDbwWriter) DeleteItems(ctx context.Context, deleteItems any, opt ...dbw.Option) (int, error) {
	return dbw.New(w.db.underlying.wrapped.Load()).DeleteItems(ctx, deleteItems, opt...)
}

func (w *changeSafeDbwWriter) DoTx(ctx context.Context, retryErrorsMatchingFn func(error) bool, retries uint, backOff dbw.Backoff, handler dbw.TxHandler) (dbw.RetryInfo, error) {
	return dbw.New(w.db.underlying.wrapped.Load()).DoTx(ctx, retryErrorsMatchingFn, retries, backOff, handler)
}

func (w *changeSafeDbwWriter) Exec(ctx context.Context, sql string, values []any, opt ...dbw.Option) (int, error) {
	return dbw.New(w.db.underlying.wrapped.Load()).Exec(ctx, sql, values, opt...)
}

func (w *changeSafeDbwWriter) Query(ctx context.Context, sql string, values []any, opt ...dbw.Option) (*sql.Rows, error) {
	return dbw.New(w.db.underlying.wrapped.Load()).Query(ctx, sql, values, opt...)
}

func (w *changeSafeDbwWriter) Rollback(ctx context.Context) error {
	return dbw.New(w.db.underlying.wrapped.Load()).Rollback(ctx)
}

func (w *changeSafeDbwWriter) ScanRows(rows *sql.Rows, result any) error {
	return dbw.New(w.db.underlying.wrapped.Load()).ScanRows(rows, result)
}

func (w *changeSafeDbwWriter) Update(ctx context.Context, i any, fieldMaskPaths []string, setToNullPaths []string, opt ...dbw.Option) (int, error) {
	return dbw.New(w.db.underlying.wrapped.Load()).Update(ctx, i, fieldMaskPaths, setToNullPaths, opt...)
}

func (w *changeSafeDbwWriter) Dialect() (_ dbw.DbType, rawName string, _ error) {
	return w.db.underlying.wrapped.Load().DbType()
}
