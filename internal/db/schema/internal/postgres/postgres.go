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
	stderrors "errors"
	"fmt"
	"io"

	"github.com/hashicorp/boundary/internal/db/schema/internal/log"
	"github.com/hashicorp/boundary/internal/db/schema/migration"
	"github.com/hashicorp/boundary/internal/db/schema/migrations"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/jackc/pgx/v5/pgconn"
)

// schemaAccessLockId is a Lock key used to ensure a single boundary binary is operating
// on a postgres server at a time.  The value has no meaning and was picked randomly.
const schemaAccessLockId int64 = 3865661975

// nilVersion is used to identify when a migration version has not be set.
const nilVersion = -1

// Postgres is a driver usable by a boundary schema.Manager.
// This struct is not thread safe.
type Postgres struct {
	// Locking and unlocking need to use the same connection
	conn *sql.Conn

	tx *sql.Tx
}

// New creates a Postgres with the provided sql.DB verified as connectable
func New(ctx context.Context, db *sql.DB) (*Postgres, error) {
	const op = "postgres.New"
	if err := db.PingContext(ctx); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	px := &Postgres{
		conn: conn,
	}
	return px, nil
}

// TrySharedLock attempts to capture a shared lock. If it is not successful it returns an error.
// https://www.postgresql.org/docs/11/static/explicit-locking.html#ADVISORY-LOCKS
func (p *Postgres) TrySharedLock(ctx context.Context) error {
	const op = "postgres.(Postgres).TrySharedLock"

	r := p.conn.QueryRowContext(ctx, trySharedLock, schemaAccessLockId)
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
// https://www.postgresql.org/docs/11/static/explicit-locking.html#ADVISORY-LOCKS
func (p *Postgres) TryLock(ctx context.Context) error {
	const op = "postgres.(Postgres).TryLock"

	r := p.conn.QueryRowContext(ctx, tryLock, schemaAccessLockId)
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

	if _, err := p.conn.ExecContext(ctx, lock, schemaAccessLockId); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

// Unlock calls pg_advisory_unlock and returns an error if we were unable to
// release the lock before the context cancels.
func (p *Postgres) Unlock(ctx context.Context) error {
	const op = "postgres.(Postgres).Unlock"

	if _, err := p.conn.ExecContext(ctx, unlock, schemaAccessLockId); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

// UnlockShared calls pg_advisory_unlock_shared and returns an error if we were unable to
// release the lock before the context cancels.
func (p *Postgres) UnlockShared(ctx context.Context) error {
	const op = "postgres.(Postgres).UnlockShared"

	if _, err := p.conn.ExecContext(ctx, unlockSharedLock, schemaAccessLockId); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

// StartRun begins a transaction internal to the driver.
func (p *Postgres) StartRun(ctx context.Context) error {
	tx, err := p.conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	p.tx = tx
	return nil
}

// CheckHook is a hook that runs prior to a migration's statements.
// It should run in the same transaction as a corresponding Run call.
func (p *Postgres) CheckHook(ctx context.Context, f migration.CheckFunc) (migration.Problems, error) {
	const op = "postgres.(Postgres).CheckHook"
	if p.tx == nil {
		return nil, errors.New(ctx, errors.MigrationIntegrity, op, "no pending transaction")
	}
	if f == nil {
		return nil, errors.New(ctx, errors.MigrationIntegrity, op, "no check function")
	}
	return f(ctx, p.tx)
}

// RepairHook is a hook that runs prior to a migration's statements.
// It should run in the same transaction a corresponding Run call.
func (p *Postgres) RepairHook(ctx context.Context, f migration.RepairFunc) (migration.Repairs, error) {
	const op = "postgres.(Postgres).RepairHook"

	if p.tx == nil {
		return nil, errors.New(ctx, errors.MigrationIntegrity, op, "no pending transaction")
	}

	if f == nil {
		return nil, errors.New(ctx, errors.MigrationIntegrity, op, "no repair function")
	}
	return f(ctx, p.tx)
}

// CommitRun commits a transaction, if there is an error it should rollback the transaction.
func (p *Postgres) CommitRun(ctx context.Context) error {
	const op = "postgres.(Postgres).CommitRun"
	defer func() {
		p.tx = nil
	}()
	if p.tx == nil {
		return errors.New(ctx, errors.MigrationIntegrity, op, "no pending transaction")
	}
	if err := p.tx.Commit(); err != nil {
		if errRollback := p.tx.Rollback(); errRollback != nil && errRollback != sql.ErrTxDone {
			err = stderrors.Join(err, errRollback)
		}
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

// Run will apply a migration. The io.Reader should provide the SQL
// statements to execute, and the int is the version for that set of
// statements. This should always be wrapped by StartRun and CommitRun.
func (p *Postgres) Run(ctx context.Context, migration io.Reader, version int, edition string) error {
	const op = "postgres.(Postgres).Run"

	if p.tx == nil {
		return errors.New(ctx, errors.MigrationIntegrity, op, "no pending transaction")
	}

	migr, err := io.ReadAll(migration)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	// Run migration
	query := string(migr)

	// set the version first, so logs will be associated with this new version.
	// if there's an error, it will get rollback
	if err := p.setVersion(ctx, version, edition); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	if _, err := p.tx.ExecContext(ctx, query); err != nil {
		if pgErr, ok := err.(*pgconn.PgError); ok {
			var line uint
			var col uint
			var lineColOK bool
			if pgErr.Position != 0 {
				line, col, lineColOK = computeLineFromPos(query, int(pgErr.Position))
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

// Close closes the underlying Postgres database connection.
func (p *Postgres) Close() error {
	return p.conn.Close()
}

var errOldMigrationTable = stderrors.New("old schema migration table")

func (p *Postgres) schemaInitialized(ctx context.Context) (bool, error) {
	const op = "postgres.(Postgres).CurrentState"
	var initialized bool

	tableNames := make([]string, 0, 2)
	tableResult, err := p.conn.QueryContext(ctx, tablesExist)
	if err != nil {
		return false, errors.Wrap(ctx, err, op)
	}
	defer tableResult.Close()
	for tableResult.Next() {
		var tableName string
		if err := tableResult.Scan(&tableName); err != nil {
			return false, errors.Wrap(ctx, err, op)
		}
		tableNames = append(tableNames, tableName)
	}

	if len(tableNames) <= 0 {
		// No version table found
		return initialized, nil
	}

	initialized = true

	if len(tableNames) > 1 {
		return initialized, errors.New(ctx, errors.MigrationIntegrity, op, "both old and new migration tables exist")
	}

	if tableNames[0] != schemaVersionTable {
		return initialized, errOldMigrationTable
	}

	return initialized, nil
}

// CurrentState returns the state of the given edition.
// ver is the current migration version number as recorded in the database.
// A version of -1 indicates no version is set.
// initialized will be true if the schema was previously initialized.
func (p *Postgres) CurrentState(ctx context.Context, edition string) (version int, initialized bool, err error) {
	const op = "postgres.(Postgres).CurrentState"

	version = nilVersion
	initialized, err = p.schemaInitialized(ctx)
	switch {
	case err == errOldMigrationTable:
		// only oss edition had the old migration table
		if edition != "oss" {
			return nilVersion, initialized, nil
		}
		err = p.conn.QueryRowContext(ctx, selectOldVersion).Scan(&version)
		switch {
		case err == sql.ErrNoRows:
			// no version recorded
			return nilVersion, initialized, nil
		case err != nil:
			return nilVersion, initialized, errors.Wrap(ctx, err, op)
		default:
			return version, initialized, nil
		}
	case err != nil:
		return nilVersion, initialized, err
	default:
		// continue
	}

	if !initialized {
		return nilVersion, initialized, nil
	}

	err = p.conn.QueryRowContext(ctx, selectVersion, edition).Scan(&version)
	switch {
	case err == sql.ErrNoRows:
		// no version recorded
		return nilVersion, initialized, nil
	case err != nil:
		// try to query for an edition in the pre-edition version table
		if edition == "oss" {
			preEditionErr := p.conn.QueryRowContext(ctx, selectPreEditionVersion).Scan(&version)
			switch {
			case preEditionErr == sql.ErrNoRows:
				return nilVersion, initialized, nil
			case preEditionErr != nil:
				// return the original error
				return nilVersion, initialized, errors.Wrap(ctx, err, op)
			default:
				return version, initialized, nil
			}
		}
		return nilVersion, initialized, errors.Wrap(ctx, err, op)
	default:
		return version, initialized, nil
	}
}

// EnsureVersionTable ensures that the table used to record the schema versions for each edition
// exists and is in the correct state.
func (p *Postgres) EnsureVersionTable(ctx context.Context) error {
	const op = "postgres.(Postgres).EnsureVersionTable"

	if p.tx == nil {
		return errors.New(ctx, errors.MigrationIntegrity, op, "no pending transaction")
	}

	exists := false
	if err := p.tx.QueryRowContext(ctx, tableExists).Scan(&exists); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	if !exists {
		oldExists := false
		if err := p.tx.QueryRowContext(ctx, oldTableExists).Scan(&oldExists); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if !oldExists {
			// create table for the first time it its correct state
			if _, err := p.tx.ExecContext(ctx, migrations.Base("postgres").CreateSchemaVersion); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		}

		// else convert old table to new table
		if _, err := p.tx.ExecContext(ctx, updateTableName); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}

	// table exists, update it to ensure it has the correct columns and constraints
	alterations := []string{
		dropDirtyColumn,
		addEditionColumn,
		setVersionNotNull,
	}

	for _, a := range alterations {
		if _, err := p.tx.ExecContext(ctx, a); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}
	return nil
}

// setVersion sets the version number, and whether the database is in a dirty state.
// A version value of -1 indicates no version is set.
func (p *Postgres) setVersion(ctx context.Context, version int, edition string) error {
	const op = "postgres.(Postgres).setVersion"

	if p.tx == nil {
		return errors.New(ctx, errors.MigrationIntegrity, op, "no pending transaction")
	}

	if _, err := p.tx.ExecContext(ctx, upsertVersion, edition, version); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	return nil
}

// EnsureMigrationLogTable ensures that the table used to record migration lgos
// exists and is in the correct state.
func (p *Postgres) EnsureMigrationLogTable(ctx context.Context) error {
	const op = "postgres.(Postgres).EnsureMigrationLogTable"

	if p.tx == nil {
		return errors.New(ctx, errors.MigrationIntegrity, op, "no pending transaction")
	}

	exists := false
	if err := p.tx.QueryRowContext(ctx, migrationLogTableExists).Scan(&exists); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	if !exists {
		if _, err := p.tx.ExecContext(ctx, migrations.Base("postgres").CreateLogMigration); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		return nil
	}

	// table exists, update it to ensure it has the correct columns and triggers
	alterations := []string{
		migrationLogAlterColumns,
		migrationLogDropTriggers,
		migrationLogAddEditionColumn,
		migrationLogReplaceVersionTrigger,
	}
	for _, a := range alterations {
		if _, err := p.tx.ExecContext(ctx, a); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}
	return nil
}

// GetMigrationLog will retrieve the migration logs from the db for the last
// migration.
// The WithDeleteLog option is supported and will remove all log entries,
// after reading the entries, when provided.
func (p *Postgres) GetMigrationLog(ctx context.Context, opt ...log.Option) ([]*log.Entry, error) {
	const op = "postgres.(Postgres).GetMigrationLog"

	rows, err := p.conn.QueryContext(ctx, getMigrationLogs)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	defer rows.Close()

	var entries []*log.Entry
	for rows.Next() {
		e := &log.Entry{}

		if err := rows.Scan(&e.Id, &e.CreateTime, &e.MigrationVersion, &e.MigrationEdition, &e.Entry); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		entries = append(entries, e)
	}
	if rows.Err() != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	opts := log.GetOpts(opt...)
	if opts.WithDeleteLog {
		// this truncate could change to a delete if FKs are needed in the future
		_, err = p.conn.ExecContext(ctx, truncateMigrationLogs)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}
	return entries, nil
}
