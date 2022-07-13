package db

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/go-dbw"
	_ "github.com/jackc/pgx/v4"
	"gorm.io/driver/postgres"
)

func init() {
	dbw.InitNonCreatableFields([]string{"CreateTime", "UpdateTime"})
	dbw.InitNonUpdatableFields([]string{"PublicId", "CreateTime", "UpdateTime"})
}

type DbType int

const (
	UnknownDB DbType = 0
	Postgres  DbType = 1
)

func (db DbType) String() string {
	return [...]string{
		"unknown",
		"postgres",
	}[db]
}

func StringToDbType(dialect string) (DbType, error) {
	switch dialect {
	case "postgres":
		return Postgres, nil
	default:
		return UnknownDB, fmt.Errorf("%s is an unknown dialect", dialect)
	}
}

// DB is a wrapper around the ORM
type DB struct {
	wrapped *dbw.DB
}

// Debug will enable/disable debug info for the connection
func (db *DB) Debug(on bool) {
	db.wrapped.Debug(on)
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
	return d.wrapped.SqlDB(ctx)
}

// Close the underlying sql.DB
func (d *DB) Close(ctx context.Context) error {
	const op = "db.(DB).Close"
	if d.wrapped == nil {
		return errors.New(ctx, errors.Internal, op, "missing underlying database")
	}
	return d.wrapped.Close(ctx)
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
	default:
		return nil, fmt.Errorf("unable to open %s database type", dbType)
	}
	opts := GetOpts(opt...)
	var wrappedOpts []dbw.Option
	if opts.withGormFormatter != nil {
		wrappedOpts = append(wrappedOpts, dbw.WithLogger(opts.withGormFormatter))
	}
	if opts.withMaxOpenConnections > 0 {
		if opts.withMaxOpenConnections < 5 {
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

	return &DB{wrapped: wrapped}, nil
}
