// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package dbw

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/jackc/pgconn"

	_ "github.com/jackc/pgx/v5" // required to load postgres drivers
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// DbType defines a database type.  It's not an exhaustive list of database
// types which can be used by the dbw package, since you can always use
// OpenWith(...) to connect to KnownDB types.
type DbType int

const (
	// UnknownDB is an unknown db type
	UnknownDB DbType = 0

	// Postgres is a postgre db type
	Postgres DbType = 1

	// Sqlite is a sqlite db type
	Sqlite DbType = 2
)

// String provides a string rep of the DbType.
func (db DbType) String() string {
	return [...]string{
		"unknown",
		"postgres",
		"sqlite",
	}[db]
}

// StringToDbType provides a string to type conversion.  If the type is known,
// then UnknownDB with and error is returned.
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

// DB is a wrapper around whatever is providing the interface for database
// operations (typically an ORM).  DB uses database/sql to maintain connection
// pool.
type DB struct {
	wrapped *gorm.DB
}

// DbType will return the DbType and raw name of the connection type
func (db *DB) DbType() (typ DbType, rawName string, e error) {
	rawName = db.wrapped.Dialector.Name()
	typ, _ = StringToDbType(rawName)
	return typ, rawName, nil
}

// Debug will enable/disable debug info for the connection
func (db *DB) Debug(on bool) {
	if on {
		// info level in the Gorm domain which maps to a debug level in this domain
		db.LogLevel(Info)
	} else {
		// the default level in the gorm domain is: error level
		db.LogLevel(Error)
	}
}

// LogLevel defines a log level
type LogLevel int

const (
	// Default specifies the default log level
	Default LogLevel = iota

	// Silent is the silent log level
	Silent

	// Error is the error log level
	Error

	// Warn is the warning log level
	Warn

	// Info is the info log level
	Info
)

// LogLevel will set the logging level for the db
func (db *DB) LogLevel(l LogLevel) {
	db.wrapped.Logger = db.wrapped.Logger.LogMode(logger.LogLevel(l))
}

// SqlDB returns the underlying sql.DB  Note: this makes it possible to do
// things like set database/sql connection options like SetMaxIdleConns. If
// you're simply setting max/min connections then you should use the
// WithMinOpenConnections and WithMaxOpenConnections options when
// "opening" the database.
//
// Care should be take when deciding to use this for basic database operations
// like Exec, Query, etc since these functions are already provided by dbw.RW
// which provides a layer of encapsulation of the underlying database.
func (db *DB) SqlDB(_ context.Context) (*sql.DB, error) {
	const op = "dbw.(DB).SqlDB"
	if db.wrapped == nil {
		return nil, fmt.Errorf("%s: missing underlying database: %w", op, ErrInternal)
	}
	return db.wrapped.DB()
}

// Close the database
//
// Note: Consider if you need to call Close() on the returned DB. Typically the
// answer is no, but there are occasions when it's necessary. See the sql.DB
// docs for more information.
func (db *DB) Close(ctx context.Context) error {
	const op = "dbw.(DB).Close"
	if db.wrapped == nil {
		return fmt.Errorf("%s: missing underlying database: %w", op, ErrInternal)
	}
	underlying, err := db.wrapped.DB()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return underlying.Close()
}

// Open a database connection which is long-lived. The options of
// WithLogger, WithLogLevel and WithMaxOpenConnections are supported.
//
// Note: Consider if you need to call Close() on the returned DB.  Typically the
// answer is no, but there are occasions when it's necessary.  See the sql.DB
// docs for more information.
func Open(dbType DbType, connectionUrl string, opt ...Option) (*DB, error) {
	const op = "dbw.Open"
	if connectionUrl == "" {
		return nil, fmt.Errorf("%s: missing connection url: %w", op, ErrInvalidParameter)
	}
	var dialect gorm.Dialector
	switch dbType {
	case Postgres:
		dialect = postgres.New(postgres.Config{
			DSN: connectionUrl,
		},
		)
	case Sqlite:
		dialect = sqlite.Open(connectionUrl)

	default:
		return nil, fmt.Errorf("unable to open %s database type", dbType)
	}
	db, err := openDialector(dialect, opt...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	if dbType == Sqlite {
		if _, err := New(db).Exec(context.Background(), "PRAGMA foreign_keys=ON", nil); err != nil {
			return nil, fmt.Errorf("%s: unable to enable sqlite foreign keys: %w", op, err)
		}
	}
	return db, nil
}

// Dialector provides a set of functions the database dialect must satisfy to
// be used with OpenWith(...)
// It's a simple wrapper of the gorm.Dialector and provides the ability to open
// any support gorm dialect driver.
type Dialector interface {
	gorm.Dialector
}

// OpenWith will open a database connection using a Dialector which is
// long-lived. The options of WithLogger, WithLogLevel and
// WithMaxOpenConnections are supported.
//
// Note: Consider if you need to call Close() on the returned DB.  Typically the
// answer is no, but there are occasions when it's necessary.  See the sql.DB
// docs for more information.
func OpenWith(dialector Dialector, opt ...Option) (*DB, error) {
	return openDialector(dialector, opt...)
}

func openDialector(dialect gorm.Dialector, opt ...Option) (*DB, error) {
	db, err := gorm.Open(dialect, &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("unable to open database: %w", err)
	}
	if strings.ToLower(dialect.Name()) == "sqlite" {
		if err := db.Exec("PRAGMA foreign_keys=ON", nil).Error; err != nil {
			return nil, fmt.Errorf("unable to enable sqlite foreign keys: %w", err)
		}
	}
	opts := GetOpts(opt...)
	if opts.WithLogger != nil {
		var newLogger logger.Interface
		loggerConfig := logger.Config{
			LogLevel: logger.LogLevel(opts.withLogLevel), // Log level
			Colorful: false,                              // Disable color
		}
		switch v := opts.WithLogger.(type) {
		case LogWriter:
			// it's already a gorm logger, so we just need to configure it
			newLogger = logger.New(v, loggerConfig)
		default:
			newLogger = logger.New(
				getGormLogger(opts.WithLogger), // wrap the hclog with a gorm logger that only logs errors
				loggerConfig,
			)
		}
		db = db.Session(&gorm.Session{Logger: newLogger})
	}
	if opts.WithMaxOpenConnections > 0 {
		if opts.WithMinOpenConnections > 0 && (opts.WithMaxOpenConnections < opts.WithMinOpenConnections) {
			return nil, fmt.Errorf("unable to create db object with dialect %s: %s", dialect, fmt.Sprintf("max_open_connections must be unlimited by setting 0 or at least %d", opts.WithMinOpenConnections))
		}
		underlyingDB, err := db.DB()
		if err != nil {
			return nil, fmt.Errorf("unable retrieve db: %w", err)
		}
		underlyingDB.SetMaxOpenConns(opts.WithMaxOpenConnections)
	}

	ret := &DB{wrapped: db}
	ret.Debug(opts.WithDebug)
	return ret, nil
}

// LogWriter defines an interface which can be used when passing a logger via
// WithLogger(...).  This interface allows callers to override the default
// behavior for a logger (the default only emits postgres errors)
type LogWriter interface {
	Printf(string, ...any)
}

type gormLogger struct {
	logger hclog.Logger
}

func (g gormLogger) Printf(_ string, values ...interface{}) {
	if len(values) > 1 {
		switch values[1].(type) {
		case *pgconn.PgError:
			g.logger.Trace("error from database adapter", "location", values[0], "error", values[1])
		}
	}
}

func getGormLogger(log hclog.Logger) gormLogger {
	return gormLogger{logger: log}
}
