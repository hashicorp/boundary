package schema

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io"
	"time"

	"github.com/hashicorp/boundary/internal/db/schema/postgres"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/go-multierror"
)

// driver provides functionality to a database.
type driver interface {
	TrySharedLock(context.Context) error
	TryLock(context.Context) error
	Lock(context.Context) error
	Unlock(context.Context) error
	UnlockShared(context.Context) error
	// Either starts a transactioon internal to the driver or sets a dirty
	// bit so if the Run fails the CurrentState reflects it.
	StartRun(context.Context) error
	// Either commits the transaction or clears the dirty bit.
	CommitRun() error
	// Performs the mutation on the driver.  This should always be
	// wrapped by StartRun and CommitRun.  The driver must properly
	// handle the transaction or dirty bit in case of error when
	// executing Run.
	Run(context.Context, io.Reader, int) error
	// A version of -1 indicates no version is set.
	CurrentState(context.Context) (ver int, everRan bool, dirty bool, err error)
	EnsureVersionTable(ctx context.Context) error
}

// Manager provides a way to run operations and retrieve information regarding
// the underlying boundary database schema.
// Manager is not thread safe.
type Manager struct {
	db              *sql.DB
	driver          driver
	dialect         string
	migrationStates map[string]migrationState
}

// NewManager creates a new schema manager. An error is returned
// if the provided dialect is unrecognized or if the passed in db is unreachable.
func NewManager(ctx context.Context, dialect string, db *sql.DB, opt ...Option) (*Manager, error) {
	const op = "schema.NewManager"
	dbM := Manager{db: db, dialect: dialect}
	opts := getOpts(opt...)
	if opts.withMigrationStates != nil {
		dbM.migrationStates = opts.withMigrationStates
	} else {
		// intentionally set it to the reference, so changes to the global var
		// will be reflected in the manager instance
		dbM.migrationStates = migrationStates
	}
	switch dialect {
	case "postgres":
		var err error
		dbM.driver, err = postgres.New(ctx, db)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	default:
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unknown dialect %q", dialect))
	}
	return &dbM, nil
}

// State contains information regarding the current state of a boundary database's schema.
type State struct {
	// InitializationStarted indicates if the current database has been initialized previously.
	InitializationStarted bool
	// Dirty is set to true if the database failed in a previous migration/initialization.
	Dirty bool
	// DatabaseSchemaVersion is the schema version that is currently running in the database.
	DatabaseSchemaVersion int
	// BinarySchemaVersion is the schema version which this boundary binary supports.
	BinarySchemaVersion int
}

// CurrentState provides the state of the boundary schema contained in the backing database.
func (b *Manager) CurrentState(ctx context.Context) (*State, error) {
	const op = "schema.(Manager).CurrentState"
	dbS := State{
		BinarySchemaVersion: BinarySchemaVersion(b.dialect),
	}

	v, initialized, dirty, err := b.driver.CurrentState(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	dbS.InitializationStarted = initialized
	dbS.DatabaseSchemaVersion = v
	dbS.Dirty = dirty
	return &dbS, nil
}

// SharedLock attempts to obtain a shared lock on the database.  This can fail
// if an exclusive lock is already held.  If the lock can't be obtained an
// error is returned.
func (b *Manager) SharedLock(ctx context.Context) error {
	const op = "schema.(Manager).SharedLock"
	if err := b.driver.TrySharedLock(ctx); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

// SharedUnlock releases a shared lock on the database.  If this
// fails for whatever reason an error is returned.  Unlocking a lock
// that is not held is not an error.
func (b *Manager) SharedUnlock(ctx context.Context) error {
	const op = "schema.(Manager).SharedUnlock"
	if err := b.driver.UnlockShared(ctx); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

// ExclusiveLock attempts to obtain an exclusive lock on the database.
// An error is returned if a lock was unable to be obtained.
func (b *Manager) ExclusiveLock(ctx context.Context) error {
	const op = "schema.(Manager).ExclusiveLock"
	if err := b.driver.TryLock(ctx); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

// ExclusiveUnlock releases a shared lock on the database.  If this
// fails for whatever reason an error is returned.  Unlocking a lock
// that is not held is not an error.
func (b *Manager) ExclusiveUnlock(ctx context.Context) error {
	const op = "schema.(Manager).ExclusiveUnlock"
	if err := b.driver.Unlock(ctx); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

// RollForward updates the database schema to match the latest version known by
// the boundary binary.  An error is not returned if the database is already at
// the most recent version.
func (b *Manager) RollForward(ctx context.Context) error {
	const op = "schema.(Manager).RollForward"

	// Capturing a lock that this session to the db already possesses is okay.
	if err := b.driver.Lock(ctx); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	defer func() {
		if err := b.driver.Unlock(ctx); err != nil {
			// I'm not sure this is ideal, but we have to rollback the current
			// transaction if we're unable to release the lock
			panic(errors.Wrap(ctx, err, op))
		}
	}()

	curVersion, _, dirty, err := b.driver.CurrentState(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	if dirty {
		return errors.New(ctx, errors.NotSpecificIntegrity, op, fmt.Sprintf("schema is dirty with version %d", curVersion))
	}

	if err = b.runMigrations(ctx, newStatementProvider(b.dialect, curVersion, WithMigrationStates(b.migrationStates))); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

type rollbacker interface {
	Rollback() error
}

// runMigrations passes migration queries to a database driver and manages
// the version and dirty bit. Cancellation or deadline/timeout is managed
// through the passed in context.
func (b *Manager) runMigrations(ctx context.Context, qp *statementProvider) error {
	const op = "schema.(Manager).runMigrations"

	if err := b.driver.StartRun(ctx); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if err := b.driver.EnsureVersionTable(ctx); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	for qp.Next() {
		select {
		case <-ctx.Done():
			err := ctx.Err()
			if d, ok := b.driver.(rollbacker); ok {
				if rbErr := d.Rollback(); rbErr != nil {
					err = multierror.Append(err, rbErr)
				}
			}
			return errors.Wrap(ctx, err, op)
		default:
			// context is not done yet. Continue on to the next query to execute.
		}
		if err := b.driver.Run(ctx, bytes.NewReader(qp.ReadUp()), qp.Version()); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}
	if err := b.driver.CommitRun(); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

// LogEntry represents a log entry generated during migrations.
type LogEntry struct {
	Id               int
	MigrationVersion string
	CreateTime       time.Time
	Entry            string
}

// GetMigrationLog will retrieve the migration logs from the db for the last
// migration. Once it's read the entries, it will delete them from the database.
//  The WithDeleteLog option is supported and will remove all log entries when provided.
func GetMigrationLog(ctx context.Context, d *sql.DB, opt ...Option) ([]LogEntry, error) {
	const op = "schema.GetMigrationLog"
	const sql = "select id, create_time, migration_version, entry from log_migration where migration_version in (select max(version) from boundary_schema_version)"
	if d == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing sql db")
	}
	rows, err := d.QueryContext(ctx, sql)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	defer rows.Close()

	var entries []LogEntry
	for rows.Next() {
		var e LogEntry
		if err := rows.Scan(&e.Id, &e.CreateTime, &e.MigrationVersion, &e.Entry); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		entries = append(entries, e)
	}
	if rows.Err() != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	opts := getOpts(opt...)
	if opts.withDeleteLog {
		// this truncate could change to a delete if FKs are needed in the future
		_, err = d.ExecContext(ctx, "truncate log_migration")
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}
	return entries, nil
}
