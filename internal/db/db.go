package db

import (
	"context"
	"database/sql"
	stderrors "errors"
	"fmt"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/go-hclog"
	"github.com/jackc/pgconn"
	_ "github.com/jackc/pgx/v4"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

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
	*gorm.DB
}

// Debug will enable/disable debug info for the connection
func (db *DB) Debug(on bool) {
	if on {
		// info level in the Gorm domain which maps to a debug level in the boundary domain
		db.Logger = logger.Default.LogMode(logger.Info)
	} else {
		// the default level in the gorm domain is: error level
		db.Logger = logger.Default.LogMode(logger.Error)
	}
}

// SqlDB returns the underlying sql.DB
//
// Note: This func is not named DB(), because our choice of ORM (gorm) which is
// embedded for various reasons, already exports a DB() func and it's base type
// is also an export DB type
func (d *DB) SqlDB(ctx context.Context) (*sql.DB, error) {
	const op = "db.(DB).SqlDB"
	if d.DB == nil {
		return nil, errors.New(ctx, errors.Internal, op, "missing underlying database")
	}
	return d.DB.DB()
}

// Close the underlying sql.DB
func (d *DB) Close(ctx context.Context) error {
	const op = "db.(DB).Close"
	if d.DB == nil {
		return errors.New(ctx, errors.Internal, op, "missing underlying database")
	}
	underlying, err := d.DB.DB()
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return underlying.Close()
}

// Open a database connection which is long-lived. The options of
// WithGormFormatter and WithMaxOpenConnections are supported.
//
// Note: Consider if you need to call Close() on the returned DB.  Typically the
// answer is no, but there are occasions when it's necessary.  See the sql.DB
// docs for more information.
func Open(dbType DbType, connectionUrl string, opt ...Option) (*DB, error) {
	var dialect gorm.Dialector
	switch dbType {
	case Postgres:
		dialect = postgres.New(postgres.Config{
			DSN: connectionUrl,
		},
		)
	default:
		return nil, fmt.Errorf("unable to open %s database type", dbType)
	}
	db, err := gorm.Open(dialect, &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("unable to open database: %w", err)
	}
	opts := GetOpts(opt...)
	if opts.withGormFormatter != nil {
		newLogger := logger.New(
			getGormLogger(opts.withGormFormatter),
			logger.Config{
				LogLevel: logger.Error, // Log level
				Colorful: false,        // Disable color
			},
		)
		db = db.Session(&gorm.Session{Logger: newLogger})
	}
	if opts.withMaxOpenConnections > 0 {
		if dialect.Name() == "postgres" && opts.withMaxOpenConnections == 1 {
			return nil, fmt.Errorf("unable to create db object with dialect %s: %s", dialect, "max_open_connections must be unlimited by setting 0 or at least 2")
		}
		underlyingDB, err := db.DB()
		if err != nil {
			return nil, fmt.Errorf("unable retreive db: %w", err)
		}
		underlyingDB.SetMaxOpenConns(opts.withMaxOpenConnections)
	}
	return &DB{db}, nil
}

func GetGormLogFormatter(log hclog.Logger) func(values ...interface{}) (messages []interface{}) {
	const op = "db.GetGormLogFormatter"
	ctx := context.TODO()
	return func(values ...interface{}) (messages []interface{}) {
		if len(values) > 2 && values[0].(string) == "log" {
			switch values[2].(type) {
			case *pgconn.PgError:
				if log.IsTrace() {
					event.WriteError(ctx, op, stderrors.New("error from database adapter"), event.WithInfo("error", values[2], "location", values[1]))
				}
			}
			return nil
		}
		return nil
	}
}

type gormLogger struct {
	logger hclog.Logger
}

func (g gormLogger) Printf(msg string, values ...interface{}) {
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
