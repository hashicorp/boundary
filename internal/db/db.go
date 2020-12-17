package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"

	"github.com/golang-migrate/migrate/v4"
	"github.com/hashicorp/boundary/internal/db/schema"
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

// Migrate a database schema
func Migrate(connectionUrl string, migrationsDirectory string) error {
	if connectionUrl == "" {
		return errors.New("connection url is unset")
	}
	if _, err := os.Stat(migrationsDirectory); os.IsNotExist(err) {
		return errors.New("error migrations directory does not exist")
	}
	// run migrations
	m, err := migrate.New(fmt.Sprintf("file://%s", migrationsDirectory), connectionUrl)
	if err != nil {
		return fmt.Errorf("unable to create migrations: %w", err)
	}
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("unable to run migrations: %w", err)
	}
	return nil
}

// InitStore will execute the migrations needed to initialize the store. It
// returns true if migrations actually ran; false if we were already current.
func InitStore(ctx context.Context, dialect string, url string) (bool, error) {
	d, err := sql.Open(dialect, url)
	if err != nil {
		return false, err
	}

	sMan, err := schema.NewManager(ctx, dialect, d)
	if err != nil {
		return false, err
	}

	st, err := sMan.State(ctx)
	if err != nil {
		return false, err
	}
	if st.Dirty {
		return false, fmt.Errorf("The passed in database has had a failed migration applied to it.")
	}

	if st.InitializationStarted && st.CurrentSchemaVersion == st.BinarySchemaVersion {
		return false, nil
	}

	if err := sMan.RollForward(ctx); err != nil {
		return false, err
	}
	return true, nil
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
