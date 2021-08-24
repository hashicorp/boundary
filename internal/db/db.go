package db

import (
	"context"
	stderrors "errors"
	"fmt"
	"math"
	"time"

	"github.com/hashicorp/boundary/internal/docker"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/go-hclog"
	"github.com/jinzhu/gorm"
	"github.com/lib/pq"
)

var (
	NegativeInfinityTS = time.Date(math.MinInt32, time.January, 1, 0, 0, 0, 0, time.UTC)
	PositiveInfinityTS = time.Date(math.MaxInt32, time.December, 31, 23, 59, 59, 1e9-1, time.UTC)
)

func init() {
	pq.EnableInfinityTs(NegativeInfinityTS, PositiveInfinityTS)
}

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

// Open a database connection which is long-lived.
// You need to call Close() on the returned gorm.DB
func Open(dbType DbType, connectionUrl string) (*gorm.DB, error) {
	db, err := gorm.Open(dbType.String(), connectionUrl)
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
			case *pq.Error:
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

func (g gormLogger) Print(values ...interface{}) {
	formatted := gorm.LogFormatter(values...)
	if formatted == nil {
		return
	}
	// Our formatter should elide anything we don't want so this should never
	// happen, panic if so so we catch/fix
	panic("unhandled error case")
}

func GetGormLogger(log hclog.Logger) gormLogger {
	return gormLogger{logger: log}
}
