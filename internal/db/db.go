// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package db

import (
	"context"
	"database/sql"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/go-dbw"
	_ "github.com/jackc/pgx/v5"
	"gorm.io/driver/postgres"
)

func init() {
	dbw.InitNonCreatableFields([]string{"CreateTime", "UpdateTime"})
	dbw.InitNonUpdatableFields([]string{"PublicId", "CreateTime", "UpdateTime"})
}

// sqliteOpen is a function used to get the dbw.Dialector for sqlite. It returns
// an error if there is any problem opening it.
var sqliteOpen = func(string) (dbw.Dialector, error) {
	return nil, fmt.Errorf("sqlite is not supported on this platform")
}

type DbType int

const (
	UnknownDB DbType = 0
	Postgres  DbType = 1
	Sqlite    DbType = 2
)

func (db DbType) String() string {
	return [...]string{
		"unknown",
		"postgres",
		"sqlite",
	}[db]
}

func StringToDbType(dialect string) (DbType, error) {
	switch dialect {
	case "postgres":
		return Postgres, nil
	case "sqlite":
		return Sqlite, nil
	default:
		return UnknownDB, fmt.Errorf("%s is an unknown dialect", dialect)
	}
}

// DB is a wrapper around the ORM
type DB struct {
	wrapped *atomic.Pointer[dbw.DB]
}

type closeDbFn func(context.Context)

var CloseSwappedDbDuration = 5 * time.Minute

// Swap replaces *DB's underlying database object with the one from `newDB`.
// It returns a function that calls Close() on the outgoing database object.
// Note: Swap does not verify the incoming *DB object is correctly set-up.
func (d *DB) Swap(ctx context.Context, newDB *DB) (closeDbFn, error) {
	const op = "db.(DB).Swap"
	if newDB == nil || newDB.wrapped == nil || newDB.wrapped.Load() == nil {
		return nil, fmt.Errorf("no new db object present")
	}
	if d == nil || d.wrapped == nil || d.wrapped.Load() == nil {
		// TBD: We could be helpful here and set the new DB instead of err?
		return nil, fmt.Errorf("no current db is present to swap, aborting")
	}

	// Grab the old db to allow for cleanup after swap.
	oldDbw := d.wrapped.Swap(newDB.wrapped.Load())
	closeOldDbFn := func(ctx context.Context) {
		go func() {
			maxTime := time.Now().Add(CloseSwappedDbDuration)
			t := time.NewTicker(time.Second)
			var done bool
			for {
				select {
				case <-t.C:
					if time.Now().After(maxTime) || done {
						t.Stop()
						if err := oldDbw.Close(ctx); err != nil {
							event.WriteError(ctx, op, errors.Wrap(ctx, err, op))
						}
						return
					}
					sqlDb, err := oldDbw.SqlDB(ctx)
					if err != nil {
						event.WriteError(ctx, op, fmt.Errorf("unable to load old sqldb to check stats"))
						continue
					}
					stats := sqlDb.Stats()
					if stats.InUse == 0 {
						done = true
					}

				case <-ctx.Done():
					t.Stop()
					event.WriteError(ctx, op, fmt.Errorf("context canceled before old database connection was closed, aborting"))
					return
				}
			}
		}()
	}

	return closeOldDbFn, nil
}

// Debug will enable/disable debug info for the connection
func (d *DB) Debug(on bool) {
	d.wrapped.Load().Debug(on)
}

// SqlDB returns the underlying sql.DB
//
// Note: This func is not named DB(), because our choice of ORM (gorm) which is
// embedded for various reasons, already exports a DB() func and it's base type
// is also an export DB type
func (d *DB) SqlDB(ctx context.Context) (*sql.DB, error) {
	const op = "db.(DB).SqlDB"
	if d.wrapped == nil {
		return nil, errors.New(ctx, errors.Internal, op, "missing underlying database")
	}
	return d.wrapped.Load().SqlDB(ctx)
}

// Close the underlying sql.DB
func (d *DB) Close(ctx context.Context) error {
	const op = "db.(DB).Close"
	if d.wrapped == nil {
		return errors.New(ctx, errors.Internal, op, "missing underlying database")
	}
	return d.wrapped.Load().Close(ctx)
}

// Open a database connection which is long-lived. The options of
// WithGormFormatter and WithMaxOpenConnections are supported.
//
// Note: Consider if you need to call Close() on the returned DB.  Typically the
// answer is no, but there are occasions when it's necessary.  See the sql.DB
// docs for more information.
func Open(ctx context.Context, dbType DbType, connectionUrl string, opt ...Option) (*DB, error) {
	const op = "db.Open"
	var dialect dbw.Dialector
	switch dbType {
	case Postgres:
		dialect = postgres.New(postgres.Config{
			DSN: connectionUrl,
		},
		)
	case Sqlite:
		var err error
		dialect, err = sqliteOpen(connectionUrl)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	default:
		return nil, fmt.Errorf("unable to open %s database type", dbType)
	}
	opts := GetOpts(opt...)
	var wrappedOpts []dbw.Option
	if opts.withGormFormatter != nil {
		wrappedOpts = append(wrappedOpts, dbw.WithLogger(opts.withGormFormatter))
	}
	if opts.withMaxOpenConnections > 0 {
		if opts.withMaxOpenConnections < 5 && dbType != Sqlite {
			return nil, fmt.Errorf("max_open_connections cannot be below 5")
		}
		wrappedOpts = append(wrappedOpts, dbw.WithMaxOpenConnections(opts.withMaxOpenConnections))
	}

	wrapped, err := dbw.OpenWith(dialect, wrappedOpts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	sdb, err := wrapped.SqlDB(ctx)
	if err != nil {
		return nil, err
	}

	if opts.withMaxIdleConnections != nil {
		sdb.SetMaxIdleConns(*opts.withMaxIdleConnections)
	}

	if opts.withConnMaxIdleTimeDuration != nil {
		sdb.SetConnMaxIdleTime(*opts.withConnMaxIdleTimeDuration)
	}

	ret := &DB{wrapped: new(atomic.Pointer[dbw.DB])}
	ret.wrapped.Store(wrapped)
	return ret, nil
}
