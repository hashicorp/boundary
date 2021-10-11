package schema

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io"

	"github.com/hashicorp/boundary/internal/db/schema/internal/edition"
	"github.com/hashicorp/boundary/internal/db/schema/internal/log"
	"github.com/hashicorp/boundary/internal/db/schema/internal/postgres"
	"github.com/hashicorp/boundary/internal/db/schema/internal/provider"
	"github.com/hashicorp/boundary/internal/errors"
)

// driver provides functionality to a database.
type driver interface {
	TrySharedLock(context.Context) error
	TryLock(context.Context) error
	Lock(context.Context) error
	Unlock(context.Context) error
	UnlockShared(context.Context) error
	// StartRun begins a transaction internal to the driver.
	StartRun(context.Context) error
	// CommitRun commits a transaction, if there is an error it should rollback the transaction.
	CommitRun(context.Context) error
	// Run will apply a migration. The io.Reader should provide the SQL
	// statements to execute, and the int is the version for that set of
	// statements. This should always be wrapped by StartRun and CommitRun.
	Run(ctx context.Context, migration io.Reader, version int, edition string) error
	// CurrentState returns the state of the given edition.
	// ver is the current migration version number as recorded in the database.
	// A version of -1 indicates no version is set.
	// initialized will be true if the schema was previously initialized.
	CurrentState(ctx context.Context, edition string) (version int, initialized bool, err error)
	// EnsureVersionTable ensures that the table used to record the schema versions for each edition
	// exists and is in the correct state.
	EnsureVersionTable(ctx context.Context) error
	// EnsureMigrationLogTable ensures that the table used to record migration lgos
	// exists and is in the correct state.
	EnsureMigrationLogTable(ctx context.Context) error
	// GetMigrationLog will retrieve the migration logs from the db for the last
	// migration.
	//  The WithDeleteLog option is supported and will remove all log entries,
	// after reading the entries, when provided.
	GetMigrationLog(ctx context.Context, opt ...log.Option) ([]*log.Entry, error)
}

// Manager provides a way to run operations and retrieve information regarding
// the underlying boundary database schema.
// Manager is not thread safe.
type Manager struct {
	db       *sql.DB
	driver   driver
	dialect  string
	editions edition.Editions
}

// NewManager creates a new schema manager. An error is returned
// if the provided dialect is unrecognized or if the passed in db is unreachable.
func NewManager(ctx context.Context, dialect Dialect, db *sql.DB, opt ...Option) (*Manager, error) {
	const op = "schema.NewManager"

	editions.Lock()
	defer editions.Unlock()

	dbM := Manager{db: db, dialect: string(dialect)}
	opts := getOpts(opt...)
	if opts.withEditions != nil {
		dbM.editions = opts.withEditions
	} else {
		dbM.editions = make(edition.Editions, 0, len(editions.m[edition.Dialect(dialect)]))
		for _, e := range editions.m[edition.Dialect(dialect)] {
			dbM.editions = append(dbM.editions, e)
		}
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

// CurrentState provides the state of the boundary schema contained in the backing database.
func (b *Manager) CurrentState(ctx context.Context) (*State, error) {
	const op = "schema.(Manager).CurrentState"
	var dbS State

	for _, e := range b.editions {
		v, initialized, err := b.driver.CurrentState(ctx, e.Name)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		dbS.Initialized = initialized || dbS.Initialized
		dbS.Editions = append(dbS.Editions, EditionState{
			Name:                  e.Name,
			DatabaseSchemaVersion: v,
			BinarySchemaVersion:   e.LatestVersion,
			DatabaseSchemaState:   compareVersions(v, e.LatestVersion),
		})
	}

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

// ApplyMigrations updates the database schema to match the latest version known by
// the boundary binary.  An error is not returned if the database is already at
// the most recent version.
func (b *Manager) ApplyMigrations(ctx context.Context) error {
	const op = "schema.(Manager).ApplyMigrations"

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

	state, err := b.CurrentState(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	if err = b.runMigrations(ctx, provider.New(state.databaseState(), b.editions)); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

// runMigrations passes migration queries to a database driver and manages
// the version and dirty bit. Cancellation or deadline/timeout is managed
// through the passed in context.
func (b *Manager) runMigrations(ctx context.Context, p *provider.Provider) (err error) {
	const op = "schema.(Manager).runMigrations"

	if startErr := b.driver.StartRun(ctx); startErr != nil {
		err = errors.Wrap(ctx, startErr, op)
		return err
	}

	defer func() {
		if commitErr := b.driver.CommitRun(ctx); commitErr != nil {
			err = errors.Wrap(ctx, commitErr, op)
		}
	}()

	if ensureErr := b.driver.EnsureVersionTable(ctx); ensureErr != nil {
		err = errors.Wrap(ctx, ensureErr, op)
		return err
	}

	if ensureErr := b.driver.EnsureMigrationLogTable(ctx); ensureErr != nil {
		err = errors.Wrap(ctx, ensureErr, op)
		return err
	}

	for p.Next() {
		select {
		case <-ctx.Done():
			err = errors.Wrap(ctx, ctx.Err(), op)
			return err
		default:
			// context is not done yet. Continue on to the next query to execute.
		}
		if runErr := b.driver.Run(ctx, bytes.NewReader(p.Statements()), p.Version(), p.Edition()); err != nil {
			err = errors.Wrap(ctx, runErr, op)
			return err
		}
	}

	return nil
}
