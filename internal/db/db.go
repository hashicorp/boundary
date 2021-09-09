package db

import (
	"context"
	stderrors "errors"
	"fmt"

	"github.com/hashicorp/boundary/internal/docker"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/go-hclog"
	"github.com/jackc/pgconn"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var StartDbInDocker = docker.StartDbInDocker

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

// Open a database connection which is long-lived.
// You need to call Close() on the returned gorm.DB
func Open(dbType DbType, connectionUrl string) (*gorm.DB, error) {
	var dialect gorm.Dialector
	switch dbType {
	case Postgres:
		dialect = postgres.New(postgres.Config{
			DSN: connectionUrl},
		)
	default:
		return nil, fmt.Errorf("unable to open %s database type", dbType)
	}
	db, err := gorm.Open(dialect, &gorm.Config{
		ConvertNullToZeroValues: true,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to open database: %w", err)
	}
	return db, nil
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

func GetGormLogger(log hclog.Logger) gormLogger {
	return gormLogger{logger: log}
}
