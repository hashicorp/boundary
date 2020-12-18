package schema

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"sort"
	"sync"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database"
	"github.com/hashicorp/boundary/internal/db/migrations"
	"github.com/hashicorp/boundary/internal/db/schema/postgres"
)

// State contains information regarding the current state of a boundary database's schema.
type State struct {
	InitializationStarted bool
	Dirty                 bool
	CurrentSchemaVersion  int
	BinarySchemaVersion   int
}

// Manager provides a way to run operations and retrieve information regarding
// the underlying boundary database schema.
type Manager struct {
	db      *sql.DB
	driver  *postgres.Postgres
	dialect string

	// GracefulStop accepts `true` and will stop executing migrations
	// as soon as possible at a safe break point, so that the database
	// is not corrupted.
	GracefulStop chan bool
	isLockedMu   *sync.Mutex

	isGracefulStop bool
	isLocked       bool
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
func (b *Manager) SharedLock(ctx context.Context, k int) error {
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
func (b *Manager) ExclusiveLock(ctx context.Context, k int) error {
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

// State provides the state of the boundary schema contained in the backing database.
func (b *Manager) State(ctx context.Context) (*State, error) {
	dbS := State{
		BinarySchemaVersion: migrations.BinarySchemaVersion,
	}
	v, dirty, err := b.driver.Version(ctx)
	if err != nil {
		return nil, err
	}
	if v == database.NilVersion {
		return &dbS, nil
	}
	dbS.InitializationStarted = true
	dbS.CurrentSchemaVersion = v
	dbS.Dirty = dirty
	return &dbS, nil
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
		return migrate.ErrDirty{curVersion}
	}

	return b.runMigrations(ctx, newQueryCommand())
}

// runMigrations passes migration queries to a database driver and manages
// the version and dirty bit.  Cancelation or deadline/timeout is managed
// through the passed in context.
func (b *Manager) runMigrations(ctx context.Context, qp queryProvider) error {
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

type queryProvider struct {
	pos      int
	versions []int
	up, down map[int][]byte
}

func newQueryCommand() queryProvider {
	qp := queryProvider{pos: -1}
	qp.up, qp.down = migrations.Queries()
	if len(qp.up) != len(qp.down) {
		fmt.Printf("Mismatch up/down size: up %d vs. down %d", len(qp.up), len(qp.down))
	}
	for k := range qp.up {
		if _, ok := qp.down[k]; !ok {
			fmt.Printf("Up key %d doesn't exist in down %v", k, qp.down)
		}
		qp.versions = append(qp.versions, k)
	}
	sort.Ints(qp.versions)

	return qp
}

func (q *queryProvider) Next() bool {
	q.pos++
	return len(q.versions) > q.pos
}

func (q *queryProvider) Version() int {
	if q.pos < 0 || q.pos >= len(q.versions) {
		return -1
	}
	return q.versions[q.pos]
}

// ReadUp reads the current up migration
func (q *queryProvider) ReadUp() []byte {
	if q.pos < 0 || q.pos >= len(q.versions) {
		return nil
	}
	return q.up[q.versions[q.pos]]
}
