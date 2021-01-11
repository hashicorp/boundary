package schema

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"

	"github.com/hashicorp/boundary/internal/errors"
)

// Manager provides a way to run operations and retrieve information regarding
// the underlying boundary database schema.
// Manager is not thread safe.
type Manager struct {
	db *sql.DB
	// TODO: Make this field be an interface when we implement a second, non-postgres, db.
	driver  *postgres
	dialect string
}

// NewManager creates a new schema manager. An error is returned
// if the provided dialect is unrecognized or if the passed in db is unreachable.
func NewManager(ctx context.Context, dialect string, db *sql.DB) (*Manager, error) {
	const op = "schema.NewManager"
	dbM := Manager{db: db, dialect: dialect}
	var err error
	switch dialect {
	case "postgres", "postgresql":
		dbM.driver, err = newPostgres(ctx, db)
		if err != nil {
			return nil, errors.Wrap(err, op)
		}
	default:
		return nil, errors.New(errors.InvalidParameter, op, fmt.Sprintf("unknown dialect %q", dialect))
	}
	return &dbM, nil
}

// SharedLock attempts to obtain a shared lock on the database.  This can fail if
// an exclusive lock is already held with the same key.  An error is returned if
// a lock was unable to be obtained.
func (b *Manager) SharedLock(ctx context.Context) error {
	const op = "schema.(Manager).SharedLock"
	if err := b.driver.trySharedLock(ctx); err != nil {
		return errors.Wrap(err, op)
	}
	return nil
}

// ExclusiveLock attempts to obtain an exclusive lock on the database.  If the
// lock can be obtained an error is returned.
func (b *Manager) ExclusiveLock(ctx context.Context) error {
	const op = "schema.(Manager).ExclusiveLock"
	if err := b.driver.tryLock(ctx); err != nil {
		return errors.Wrap(err, op)
	}
	return nil
}

// RollForward updates the database schema to match the latest version known by
// the boundary binary.  An error is not returned if the database is already at
// the most recent version.
func (b *Manager) RollForward(ctx context.Context) error {
	const op = "schema.(Manager).RollForward"

	// Capturing a lock that this session to the db already possesses is okay.
	if err := b.driver.lock(ctx); err != nil {
		return errors.Wrap(err, op)
	}
	defer func() {
		b.driver.unlock(ctx)
	}()

	curVersion, dirty, err := b.driver.version(ctx)
	if err != nil {
		return errors.Wrap(err, op)
	}

	if dirty {
		return errors.New(errors.NotSpecificIntegrity, op, fmt.Sprintf("schema is dirty with version %d", curVersion))
	}

	sp, err := newStatementProvider(b.dialect, curVersion)
	if err != nil {
		return errors.Wrap(err, op)
	}
	return b.runMigrations(ctx, sp)
}

// runMigrations passes migration queries to a database driver and manages
// the version and dirty bit.  Cancelation or deadline/timeout is managed
// through the passed in context.
func (b *Manager) runMigrations(ctx context.Context, qp *statementProvider) error {
	const op = "schema.(Manager).runMigrations"
	for qp.Next() {
		select {
		case <-ctx.Done():
			return errors.Wrap(ctx.Err(), op)
		default:
			// context is not done yet. Continue on to the next query to execute.
		}

		// set version with dirty state
		if err := b.driver.setVersion(ctx, qp.Version(), true); err != nil {
			return errors.Wrap(err, op)
		}

		if err := b.driver.run(ctx, bytes.NewReader(qp.ReadUp())); err != nil {
			return errors.Wrap(err, op)
		}

		// set clean state
		if err := b.driver.setVersion(ctx, qp.Version(), false); err != nil {
			return errors.Wrap(err, op)
		}
	}
	return nil
}
