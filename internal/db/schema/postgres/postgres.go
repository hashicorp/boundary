// The MIT License (MIT)
//
// Original Work
// Copyright (c) 2016 Matthias Kadenbach
// https://github.com/mattes/migrate
//
// Modified Work
// Copyright (c) 2018 Dale Hui
// https://github.com/golang-migrate/migrate
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"io/ioutil"
	"strconv"
	"strings"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/go-multierror"
	"github.com/lib/pq"
)

// schemaAccessLockId is a Lock key used to ensure a single boundary binary is operating
// on a postgres server at a time.  The value has no meaning and was picked randomly.
const (
	schemaAccessLockId int64 = 3865661975
	nilVersion               = -1
)

var defaultMigrationsTable = "boundary_schema_version"

// Postgres is a driver usable by a boundary schema manager.
// This struct is not thread safe.
type Postgres struct {
	// Locking and unlocking need to use the same connection
	conn *sql.Conn
	db   *sql.DB

	tx *sql.Tx
}

// New returns a postgres pointer with the provided db verified as
// connectable and a version table being initialized.
func New(ctx context.Context, instance *sql.DB) (*Postgres, error) {
	const op = "postgres.New"
	if err := instance.PingContext(ctx); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	conn, err := instance.Conn(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	px := &Postgres{
		conn: conn,
		db:   instance,
	}
	return px, nil
}

// TrySharedLock attempts to capture a shared lock. If it is not successful it returns an error.
// https://www.postgresql.org/docs/9.6/static/explicit-locking.html#ADVISORY-LOCKS
func (p *Postgres) TrySharedLock(ctx context.Context) error {
	const op = "postgres.(Postgres).TrySharedLock"
	const query = "select pg_try_advisory_lock_shared($1)"
	r := p.conn.QueryRowContext(ctx, query, schemaAccessLockId)
	if r.Err() != nil {
		return errors.Wrap(ctx, r.Err(), op)
	}
	var gotLock bool
	if err := r.Scan(&gotLock); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if !gotLock {
		return errors.New(ctx, errors.MigrationLock, op, "Lock failed")
	}
	return nil
}

// TryLock attempts to capture an exclusive lock. If it is not successful it returns an error.
// https://www.postgresql.org/docs/9.6/static/explicit-locking.html#ADVISORY-LOCKS
func (p *Postgres) TryLock(ctx context.Context) error {
	const op = "postgres.(Postgres).TryLock"
	const query = "select pg_try_advisory_lock($1)"
	r := p.conn.QueryRowContext(ctx, query, schemaAccessLockId)
	if r.Err() != nil {
		return errors.Wrap(ctx, r.Err(), op)
	}
	var gotLock bool
	if err := r.Scan(&gotLock); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if !gotLock {
		return errors.New(ctx, errors.MigrationLock, op, "Lock failed")
	}
	return nil
}

// Lock calls pg_advisory_lock with the provided context and returns an error
// if we were unable to get the lock before the context cancels.
func (p *Postgres) Lock(ctx context.Context) error {
	const op = "postgres.(Postgres).Lock"
	const query = "select pg_advisory_lock($1)"
	if _, err := p.conn.ExecContext(ctx, query, schemaAccessLockId); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

// Unlock calls pg_advisory_unlock and returns an error if we were unable to
// release the lock before the context cancels.
func (p *Postgres) Unlock(ctx context.Context) error {
	const op = "postgres.(Postgres).Unlock"
	const query = `select pg_advisory_unlock($1)`
	if _, err := p.conn.ExecContext(ctx, query, schemaAccessLockId); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

// UnlockShared calls pg_advisory_unlock_shared and returns an error if we were unable to
// release the lock before the context cancels.
func (p *Postgres) UnlockShared(ctx context.Context) error {
	const op = "postgres.(Postgres).UnlockShared"
	query := `select pg_advisory_unlock_shared($1)`
	if _, err := p.conn.ExecContext(ctx, query, schemaAccessLockId); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

// Rollback rolls back the outstanding transaction.
// Calling Rollback when there is not an outstanding transaction is an error.
func (p *Postgres) Rollback() error {
	const op = "postgres.(Postgres).Rollback"
	defer func() {
		p.tx = nil
	}()
	if p.tx == nil {
		return errors.NewDeprecated(errors.MigrationIntegrity, op, "no pending transaction")
	}
	if err := p.tx.Rollback(); err != nil {
		return errors.WrapDeprecated(err, op)
	}
	return nil
}

// StartRun starts a transaction that all subsequent calls to Run will use.
func (p *Postgres) StartRun(ctx context.Context) error {
	tx, err := p.conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	p.tx = tx
	return nil
}

// CommitRun commits the pending transaction if there is one
func (p *Postgres) CommitRun() error {
	const op = "postgres.(Postgres).CommitRun"
	defer func() {
		p.tx = nil
	}()
	if p.tx == nil {
		return errors.NewDeprecated(errors.MigrationIntegrity, op, "no pending transaction")
	}
	if err := p.tx.Commit(); err != nil {
		if errRollback := p.tx.Rollback(); errRollback != nil {
			err = multierror.Append(err, errRollback)
		}
		return errors.WrapDeprecated(err, op)
	}
	return nil
}

type execContexter interface {
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
}

// Run executes the sql provided in the passed in io.Reader.  The contents of the reader must
// fit in memory as the full content is read into a string before being passed to the
// backing database.  EnsureVersionTable should be ran prior to this call.
func (p *Postgres) Run(ctx context.Context, migration io.Reader, version int) error {
	const op = "postgres.(Postgres).Run"
	migr, err := ioutil.ReadAll(migration)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	// Run migration
	query := string(migr)

	var extr execContexter = p.conn
	rollback := func() error { return nil }
	if p.tx != nil {
		extr = p.tx
		rollback = func() error {
			defer func() { p.tx = nil }()
			return p.tx.Rollback()
		}
	}

	// set the version first, so logs will be associated with this new version.
	// if there's an error, it will get rollback
	if err := p.setVersion(ctx, version, false); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	if _, err := extr.ExecContext(ctx, query); err != nil {
		if rollbackErr := rollback(); rollbackErr != nil {
			err = multierror.Append(err, rollbackErr)
		}
		if pgErr, ok := err.(*pq.Error); ok {
			var line uint
			var col uint
			var lineColOK bool
			if pgErr.Position != "" {
				if pos, err := strconv.ParseUint(pgErr.Position, 10, 64); err == nil {
					line, col, lineColOK = computeLineFromPos(query, int(pos))
				}
			}
			message := "migration failed"
			if lineColOK {
				message = fmt.Sprintf("%s (column %d)", message, col)
			}
			if pgErr.Detail != "" {
				message = fmt.Sprintf("%s, %s", message, pgErr.Detail)
			}
			message = fmt.Sprintf("%s, on line %v: %s", message, line, migr)
			return errors.Wrap(ctx, err, op, errors.WithMsg(message))
		}
		return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("migration failed: %s", migr)))
	}

	return nil
}

func computeLineFromPos(s string, pos int) (line uint, col uint, ok bool) {
	// replace crlf with lf
	s = strings.Replace(s, "\r\n", "\n", -1)
	// pg docs: pos uses index 1 for the first character, and positions are measured in characters not bytes
	runes := []rune(s)
	if pos > len(runes) {
		return 0, 0, false
	}
	sel := runes[:pos]
	line = uint(runesCount(sel, newLine) + 1)
	col = uint(pos - 1 - runesLastIndex(sel, newLine))
	return line, col, true
}

const newLine = '\n'

func runesCount(input []rune, target rune) int {
	var count int
	for _, r := range input {
		if r == target {
			count++
		}
	}
	return count
}

func runesLastIndex(input []rune, target rune) int {
	for i := len(input) - 1; i >= 0; i-- {
		if input[i] == target {
			return i
		}
	}
	return -1
}

// setVersion sets the version number, and whether the database is in a dirty state.
// A version value of -1 indicates no version is set.
func (p *Postgres) setVersion(ctx context.Context, version int, dirty bool) error {
	const op = "postgres.(Postgres).SetVersion"
	tx := p.tx
	var err error
	if tx == nil {
		tx, err = p.conn.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
	}
	rollback := func() error {
		defer func() { p.tx = nil }()
		return tx.Rollback()
	}

	query := `truncate ` + pq.QuoteIdentifier(defaultMigrationsTable)
	if _, err := tx.ExecContext(ctx, query); err != nil {
		if errRollback := rollback(); errRollback != nil {
			err = multierror.Append(err, errRollback)
		}
		return errors.Wrap(ctx, err, op)
	}

	// Also re-write the schema Version for nil dirty versions to prevent
	// empty schema Version for failed down migration on the first migration
	// See: https://github.com/golang-migrate/migrate/issues/330
	if version >= 0 || (version == nilVersion && dirty) {
		query = `insert into ` + pq.QuoteIdentifier(defaultMigrationsTable) +
			` (version, dirty) values ($1, $2)`
		if _, err := tx.ExecContext(ctx, query, version, dirty); err != nil {
			if errRollback := rollback(); errRollback != nil {
				err = multierror.Append(err, errRollback)
			}
			return errors.Wrap(ctx, err, op)
		}
	}

	if p.tx == nil {
		if err := tx.Commit(); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}
	return nil
}

// CurrentState returns the version, if the database was ever initialized
// previously, if it is currently in a dirty state, and any error. A version
// value of -1 indicates no version is set.
func (p *Postgres) CurrentState(ctx context.Context) (version int, previouslyRan, dirty bool, err error) {
	const op = "postgres.(Postgres).CurrentState"

	version = nilVersion
	previouslyRan, dirty = false, false

	tableQuery := `select table_name from information_schema.tables where table_schema=(select current_schema()) and table_name in ('schema_migrations', '` + defaultMigrationsTable + `')`
	tableResult, err := p.conn.QueryContext(ctx, tableQuery)
	if err != nil {
		return nilVersion, previouslyRan, dirty, errors.Wrap(ctx, err, op)
	}
	defer tableResult.Close()
	if !tableResult.Next() {
		// No version table found
		return nilVersion, previouslyRan, dirty, nil
	}

	tableName := defaultMigrationsTable
	if err := tableResult.Scan(&tableName); err != nil {
		return nilVersion, previouslyRan, dirty, errors.Wrap(ctx, err, op)
	}
	previouslyRan = true
	if tableResult.Next() {
		return nilVersion, previouslyRan, dirty, errors.New(ctx, errors.MigrationIntegrity, op, "both old and new migration tables exist")
	}

	query := `select version, dirty from ` + pq.QuoteIdentifier(tableName)
	results, err := p.conn.QueryContext(ctx, query)
	if err != nil {
		return nilVersion, previouslyRan, dirty, errors.Wrap(ctx, err, op)
	}
	defer results.Close()
	if !results.Next() {
		// no version recorded
		return nilVersion, previouslyRan, dirty, nil
	}
	if err := results.Scan(&version, &dirty); err != nil {
		return nilVersion, previouslyRan, dirty, errors.Wrap(ctx, err, op)
	}
	if results.Next() {
		return nilVersion, previouslyRan, dirty, errors.New(ctx, errors.MigrationIntegrity, op, "to many versions in version table")
	}
	return version, previouslyRan, dirty, nil
}

func (p *Postgres) drop(ctx context.Context) (err error) {
	const op = "postgres.(Postgres).drop"
	// select all tables in current schema
	query := `select table_name from information_schema.tables where table_schema=(select current_schema()) and table_type='BASE TABLE'`
	tables, err := p.conn.QueryContext(ctx, query)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	defer func() {
		if errClose := tables.Close(); errClose != nil {
			err = multierror.Append(err, errClose)
			err = errors.Wrap(ctx, err, op)
		}
	}()

	// delete one table after another
	tableNames := make([]string, 0)
	for tables.Next() {
		var tableName string
		if err := tables.Scan(&tableName); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if len(tableName) > 0 {
			tableNames = append(tableNames, tableName)
		}
	}
	if err := tables.Err(); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	if len(tableNames) > 0 {
		// delete one by one ...
		for _, t := range tableNames {
			query = `drop table if exists ` + pq.QuoteIdentifier(t) + ` cascade`
			if _, err := p.conn.ExecContext(ctx, query); err != nil {
				return errors.Wrap(ctx, err, op)
			}
		}
	}

	return nil
}

// EnsureVersionTable checks if versions table exists and, if not, creates it.
func (p *Postgres) EnsureVersionTable(ctx context.Context) (err error) {
	const op = "postgres.(Postgres).EnsureVersionTable"

	var extr execContexter = p.conn
	rollback := func() error { return nil }
	if p.tx != nil {
		extr = p.tx
		rollback = func() error {
			defer func() { p.tx = nil }()
			return p.tx.Rollback()
		}
	}

	query := `select exists (select 1 from information_schema.tables where table_schema=(select current_schema()) and table_name = '` + defaultMigrationsTable + `');`
	exists := false
	if err := extr.QueryRowContext(ctx, query).Scan(&exists); err != nil {
		if wpErr := rollback(); wpErr != nil {
			err = multierror.Append(err, wpErr)
		}
		return errors.Wrap(ctx, err, op)
	}
	if exists {
		return nil
	}

	updateQuery := `alter table if exists schema_migrations rename to ` + defaultMigrationsTable + `;`
	if _, err = extr.ExecContext(ctx, updateQuery); err != nil {
		if wpErr := rollback(); wpErr != nil {
			err = multierror.Append(err, wpErr)
		}
		return errors.Wrap(ctx, err, op)
	}

	createStmt := `create table if not exists ` + pq.QuoteIdentifier(defaultMigrationsTable) + ` (version bigint primary key, dirty boolean not null)`
	if _, err = extr.ExecContext(ctx, createStmt); err != nil {
		if wpErr := rollback(); wpErr != nil {
			err = multierror.Append(err, wpErr)
		}
		return errors.Wrap(ctx, err, op)
	}

	return nil
}
