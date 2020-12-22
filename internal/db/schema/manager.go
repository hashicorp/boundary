package schema

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"

	"github.com/hashicorp/boundary/internal/db/schema/postgres"
)

type SchemaLockKey uint

const SchemaAccessLockId SchemaLockKey = 3865661975

type ErrDirty struct {
	Version int
}

func (e ErrDirty) Error() string {
	return fmt.Sprintf("Dirty database version %v. Fix and force version.", e.Version)
}

// Manager provides a way to run operations and retrieve information regarding
// the underlying boundary database schema.
// Manager is not thread safe.
type Manager struct {
	db      *sql.DB
	driver  *postgres.Postgres
	dialect string
}

// NewManager creates a new schema manager. An error is returned
// if the provided dialect is unrecognized or if the passed in db is unreachable.
func NewManager(ctx context.Context, dialect string, db *sql.DB) (*Manager, error) {
	dbM := Manager{db: db, dialect: dialect}
	var err error
	switch dialect {
	case "postgres", "postgresql":
		dbM.driver, err = postgres.WithInstance(ctx, db, &postgres.Config{
			MigrationsTable: "boundary_schema_version",
		})
		if err != nil {
			return nil, fmt.Errorf("Error creating database driver: %w", err)
		}
	default:
		return nil, fmt.Errorf("Provided unknown dialect %q", dialect)
	}
	return &dbM, nil
}

// SharedLock attempts to obtain a shared lock on the database.  This can fail if
// an exclusive lock is already held with the same key.  An error is returned if
// a lock was unable to be obtained.
func (b *Manager) SharedLock(ctx context.Context, k SchemaLockKey) error {
	lockErr := fmt.Errorf("Unable to obtain the shared advisory lock %q", k)
	r := b.db.QueryRowContext(ctx, "SELECT pg_try_advisory_lock_shared($1)", k)
	if r.Err() != nil {
		return lockErr
	}
	var gotLock bool
	if err := r.Scan(&gotLock); err != nil || !gotLock {
		return lockErr
	}

	return nil
}

// ExclusiveLock attempts to obtain an exclusive lock on the database.  If the
// lock can be obtained an error is returned.
func (b *Manager) ExclusiveLock(ctx context.Context, k SchemaLockKey) error {
	lockErr := fmt.Errorf("Unable to obtain the exclusive advisory lock %q", k)
	r := b.db.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", k)
	if r.Err() != nil {
		return lockErr
	}
	var gotLock bool
	if err := r.Scan(&gotLock); err != nil || !gotLock {
		return lockErr
	}
	return nil
}

// RollForward updates the database schema to match the latest version known by
// the boundary binary.  An error is not returned if the database is already at
// the most recent version.
func (b *Manager) RollForward(ctx context.Context) error {
	if err := b.driver.Lock(ctx); err != nil {
		return err
	}
	defer func() {
		b.driver.Unlock(ctx)
	}()

	curVersion, dirty, err := b.driver.Version(ctx)
	if err != nil {
		return err
	}

	if dirty {
		return ErrDirty{curVersion}
	}

	return b.runMigrations(ctx, newStatementProvider(b.dialect, curVersion))
}

// runMigrations passes migration queries to a database driver and manages
// the version and dirty bit.  Cancelation or deadline/timeout is managed
// through the passed in context.
func (b *Manager) runMigrations(ctx context.Context, qp statementProvider) error {
	for qp.Next() {
		select {
		case <-ctx.Done():
			return fmt.Errorf("Stopped during runMigrations: %w", ctx.Err())
		default:
			// context is not done yet. Continue on to the next query to execute.
		}

		// set version with dirty state
		if err := b.driver.SetVersion(ctx, qp.Version(), true); err != nil {
			return err
		}

		if err := b.driver.Run(ctx, bytes.NewReader(qp.ReadUp())); err != nil {
			return err
		}

		// set clean state
		if err := b.driver.SetVersion(ctx, qp.Version(), false); err != nil {
			return err
		}
	}
	return nil
}
