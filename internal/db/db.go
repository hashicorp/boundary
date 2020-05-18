package db

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/watchtower/internal/db/migrations"
	"github.com/jinzhu/gorm"
	"github.com/ory/dockertest"
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

// InitDbInDocker initializes the data store within docker or an existing PG_URL
func InitDbInDocker(dialect string) (cleanup func() error, retURL, container string, err error) {
	switch dialect {
	case "postgres":
		if os.Getenv("PG_URL") != "" {
			if err := InitStore(dialect, func() error { return nil }, os.Getenv("PG_URL")); err != nil {
				return func() error { return nil }, os.Getenv("PG_URL"), "", fmt.Errorf("error initializing store: %w", err)
			}
			return func() error { return nil }, os.Getenv("PG_URL"), "", nil
		}
	}
	c, url, container, err := StartDbInDocker(dialect)
	if err != nil {
		return func() error { return nil }, "", "", fmt.Errorf("could not start docker: %w", err)
	}
	if err := InitStore(dialect, c, url); err != nil {
		return func() error { return nil }, "", "", fmt.Errorf("error initializing store: %w", err)
	}
	return c, url, container, nil
}

// StartDbInDocker
func StartDbInDocker(dialect string) (cleanup func() error, retURL, container string, err error) {
	pool, err := dockertest.NewPool("")
	if err != nil {
		return func() error { return nil }, "", "", fmt.Errorf("could not connect to docker: %w", err)
	}

	var resource *dockertest.Resource
	var url string
	switch dialect {
	case "postgres":
		resource, err = pool.Run("postgres", "latest", []string{"POSTGRES_PASSWORD=secret", "POSTGRES_DB=watchtower"})
		url = "postgres://postgres:secret@localhost:%s?sslmode=disable"
	default:
		panic(fmt.Sprintf("unknown dialect %q", dialect))
	}
	if err != nil {
		return func() error { return nil }, "", "", fmt.Errorf("could not start resource: %w", err)
	}

	cleanup = func() error {
		return cleanupDockerResource(pool, resource)
	}

	url = fmt.Sprintf(url, resource.GetPort("5432/tcp"))

	if err := pool.Retry(func() error {
		db, err := sql.Open(dialect, url)
		if err != nil {
			return fmt.Errorf("error opening %s dev container: %w", dialect, err)
		}

		if err := db.Ping(); err != nil {
			return err
		}
		defer db.Close()
		return nil
	}); err != nil {
		return func() error { return nil }, "", "", fmt.Errorf("could not connect to docker: %w", err)
	}

	return cleanup, url, resource.Container.Name, nil
}

// InitStore will execute the migrations needed to initialize the store for tests
func InitStore(dialect string, cleanup func() error, url string) error {
	var mErr *multierror.Error
	// run migrations
	source, err := migrations.NewMigrationSource(dialect)
	if err != nil {
		mErr = multierror.Append(mErr, fmt.Errorf("error creating migration driver: %w", err))
		if err := cleanup(); err != nil {
			mErr = multierror.Append(mErr, err)
		}
		return mErr.ErrorOrNil()
	}
	m, err := migrate.NewWithSourceInstance("httpfs", source, url)
	if err != nil {
		mErr = multierror.Append(mErr, fmt.Errorf("error creating migrations: %w", err))
		if err := cleanup(); err != nil {
			mErr = multierror.Append(mErr, err)
		}
		return mErr.ErrorOrNil()

	}
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		mErr = multierror.Append(mErr, fmt.Errorf("error running migrations: %w", err))
		if err := cleanup(); err != nil {
			mErr = multierror.Append(mErr, err)
		}
		return mErr.ErrorOrNil()
	}
	return mErr.ErrorOrNil()
}

// cleanupDockerResource will clean up the dockertest resources (postgres)
func cleanupDockerResource(pool *dockertest.Pool, resource *dockertest.Resource) error {
	var err error
	for i := 0; i < 10; i++ {
		err = pool.Purge(resource)
		if err == nil {
			return nil
		}
	}
	if strings.Contains(err.Error(), "No such container") {
		return nil
	}
	return fmt.Errorf("Failed to cleanup local container: %s", err)
}
