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
const schemaAccessLockId = 3865661975
const nilVersion = -1

var defaultMigrationsTable = "boundary_schema_version"

// Postgres is a driver usable by a boundary schema manager.
type Postgres struct {
	// Locking and unlocking need to use the same connection
	conn *sql.Conn
	db   *sql.DB
}

// NewPostgres returns a postgres pointer with the provided db verified as
// connectable and a version table being initialized.
func NewPostgres(ctx context.Context, instance *sql.DB) (*Postgres, error) {
	const op = "postgres.NewPostgres"
	if err := instance.PingContext(ctx); err != nil {
		return nil, errors.Wrap(err, op)
	}
	conn, err := instance.Conn(ctx)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}

	px := &Postgres{
		conn: conn,
		db:   instance,
	}

	if err := px.ensureVersionTable(ctx); err != nil {
		return nil, errors.Wrap(err, op)
	}

	return px, nil
}

// TrySharedLock attempts to capture a shared lock. If it is not successful it returns an error.
// https://www.postgresql.org/docs/9.6/static/explicit-locking.html#ADVISORY-LOCKS
func (p *Postgres) TrySharedLock(ctx context.Context) error {
	const op = "postgres.(Postgres).TrySharedLock"
	r := p.db.QueryRowContext(ctx, "SELECT pg_try_advisory_lock_shared($1)", schemaAccessLockId)
	if r.Err() != nil {
		return errors.Wrap(r.Err(), op)
	}
	var gotLock bool
	if err := r.Scan(&gotLock); err != nil {
		return errors.Wrap(err, op)
	}
	if !gotLock {
		return errors.New(errors.MigrationLock, op, "Lock failed")
	}
	return nil
}

// TryLock attempts to capture an exclusive lock. If it is not successful it returns an error.
// https://www.postgresql.org/docs/9.6/static/explicit-locking.html#ADVISORY-LOCKS
func (p *Postgres) TryLock(ctx context.Context) error {
	const op = "postgres.(Postgres).TryLock"

	r := p.db.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", schemaAccessLockId)
	if r.Err() != nil {
		return errors.Wrap(r.Err(), op)
	}
	var gotLock bool
	if err := r.Scan(&gotLock); err != nil {
		return errors.Wrap(err, op)
	}
	if !gotLock {
		return errors.New(errors.MigrationLock, op, "Lock failed")
	}
	return nil
}

// Lock calls pg_advisory_lock with the provided context and returns an error if one is returned.
func (p *Postgres) Lock(ctx context.Context) error {
	const op = "postgres.(Postgres).Lock"

	// This will wait indefinitely until the Lock can be acquired.
	query := `SELECT pg_advisory_lock($1)`
	if _, err := p.conn.ExecContext(ctx, query, schemaAccessLockId); err != nil {
		return errors.Wrap(err, op)
	}

	return nil
}

// Unlock calls pg_advisory_unlock and returns an error if one is returned.
func (p *Postgres) Unlock(ctx context.Context) error {
	const op = "postgres.(Postgres).Unlock"

	query := `SELECT pg_advisory_unlock($1)`
	if _, err := p.conn.ExecContext(ctx, query, schemaAccessLockId); err != nil {
		return errors.Wrap(err, op)
	}
	return nil
}

// Executes the sql provided in the passed in io.Reader.  The contents of the reader must
// fit in memory as the full content is read into a string before being passed to the
// backing database.
func (p *Postgres) Run(ctx context.Context, migration io.Reader) error {
	const op = "postgres.(Postgres).Run"
	migr, err := ioutil.ReadAll(migration)
	if err != nil {
		return errors.Wrap(err, op)
	}
	// Run migration
	query := string(migr[:])
	if _, err := p.conn.ExecContext(ctx, query); err != nil {
		if pgErr, ok := err.(*pq.Error); ok {
			var line uint
			var col uint
			var lineColOK bool
			if pgErr.Position != "" {
				if pos, err := strconv.ParseUint(pgErr.Position, 10, 64); err == nil {
					line, col, lineColOK = computeLineFromPos(query, int(pos))
				}
			}
			message := fmt.Sprintf("migration failed")
			if lineColOK {
				message = fmt.Sprintf("%s (column %d)", message, col)
			}
			if pgErr.Detail != "" {
				message = fmt.Sprintf("%s, %s", message, pgErr.Detail)
			}
			message = fmt.Sprintf("%s, on line %v: %s", message, line, migr)
			return errors.Wrap(err, op, errors.WithMsg(message))
		}
		return errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("migration failed: %s", migr)))
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

// SetVersion sets the version number, and whether the database is in a dirty state.
// A version value of -1 indicates no version is set.
func (p *Postgres) SetVersion(ctx context.Context, version int, dirty bool) error {
	const op = "postgres.(Postgres).SetVersion"
	tx, err := p.conn.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return err
	}

	query := `TRUNCATE ` + pq.QuoteIdentifier(defaultMigrationsTable)
	if _, err := tx.ExecContext(ctx, query); err != nil {
		if errRollback := tx.Rollback(); errRollback != nil {
			err = multierror.Append(err, errRollback)
		}
		return errors.Wrap(err, op)
	}

	// Also re-write the schema Version for nil dirty versions to prevent
	// empty schema Version for failed down migration on the first migration
	// See: https://github.com/golang-migrate/migrate/issues/330
	if version >= 0 || (version == nilVersion && dirty) {
		query = `INSERT INTO ` + pq.QuoteIdentifier(defaultMigrationsTable) +
			` (Version, dirty) VALUES ($1, $2)`
		if _, err := tx.ExecContext(ctx, query, version, dirty); err != nil {
			if errRollback := tx.Rollback(); errRollback != nil {
				err = multierror.Append(err, errRollback)
			}
			return errors.Wrap(err, op)
		}
	}

	if err := tx.Commit(); err != nil {
		return errors.Wrap(err, op)
	}

	return nil
}

// Version returns the version, if the database is currently in a dirty state, and any error.
// A version value of -1 indicates no version is set.
func (p *Postgres) Version(ctx context.Context) (version int, dirty bool, err error) {
	const op = "postgres.(Postgres).Version"
	query := `SELECT Version, dirty FROM ` + pq.QuoteIdentifier(defaultMigrationsTable) + ` LIMIT 1`
	err = p.conn.QueryRowContext(ctx, query).Scan(&version, &dirty)
	switch {
	case err == sql.ErrNoRows:
		return nilVersion, false, nil

	case err != nil:
		if e, ok := err.(*pq.Error); ok {
			if e.Code.Name() == "undefined_table" {
				return nilVersion, false, nil
			}
		}
		return 0, false, errors.Wrap(err, op)

	default:
		return version, dirty, nil
	}
}

func (p *Postgres) drop(ctx context.Context) (err error) {
	const op = "postgres.(Postgres).drop"
	// select all tables in current schema
	query := `SELECT table_name FROM information_schema.tables WHERE table_schema=(SELECT current_schema()) AND table_type='BASE TABLE'`
	tables, err := p.conn.QueryContext(ctx, query)
	if err != nil {
		return errors.Wrap(err, op)
	}
	defer func() {
		if errClose := tables.Close(); errClose != nil {
			err = multierror.Append(err, errClose)
			err = errors.Wrap(err, op)
		}
	}()

	// delete one table after another
	tableNames := make([]string, 0)
	for tables.Next() {
		var tableName string
		if err := tables.Scan(&tableName); err != nil {
			return errors.Wrap(err, op)
		}
		if len(tableName) > 0 {
			tableNames = append(tableNames, tableName)
		}
	}
	if err := tables.Err(); err != nil {
		return errors.Wrap(err, op)
	}

	if len(tableNames) > 0 {
		// delete one by one ...
		for _, t := range tableNames {
			query = `DROP TABLE IF EXISTS ` + pq.QuoteIdentifier(t) + ` CASCADE`
			if _, err := p.conn.ExecContext(ctx, query); err != nil {
				return errors.Wrap(err, op)
			}
		}
	}

	return nil
}

// ensureVersionTable checks if versions table exists and, if not, creates it.
// Note that this function locks the database, which deviates from the usual
// convention of "caller locks" in the postgres type.
func (p *Postgres) ensureVersionTable(ctx context.Context) (err error) {
	const op = "postgres.(Postgres).ensureVersionTable"
	if err = p.Lock(ctx); err != nil {
		return errors.Wrap(err, op)
	}

	defer func() {
		if e := p.Unlock(ctx); e != nil {
			err = multierror.Append(err, e)
		}
	}()

	query := `CREATE TABLE IF NOT EXISTS ` + pq.QuoteIdentifier(defaultMigrationsTable) + ` (Version bigint not null primary key, dirty boolean not null)`
	if _, err = p.conn.ExecContext(ctx, query); err != nil {
		return errors.Wrap(err, op)
	}

	return nil
}
