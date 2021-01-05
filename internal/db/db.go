package db

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/docker"
	"github.com/hashicorp/go-hclog"
	"github.com/jinzhu/gorm"
	"github.com/lib/pq"
)

var (
	StartDbInDocker = docker.StartDbInDocker
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
	return func(values ...interface{}) (messages []interface{}) {
		if len(values) > 2 && values[0].(string) == "log" {
			switch values[2].(type) {
			case *pq.Error:
				log.Trace("error from database adapter", "location", values[1], "error", values[2])
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
