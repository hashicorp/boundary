package db

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/golang-migrate/migrate/v4"
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

// StartDbInDocker
func StartDbInDocker() (cleanup func() error, retURL string, err error) {
	pool, err := dockertest.NewPool("")
	if err != nil {
		return func() error { return nil }, "", fmt.Errorf("could not connect to docker: %w", err)
	}

	resource, err := pool.Run("postgres", "latest", []string{"POSTGRES_PASSWORD=secret", "POSTGRES_DB=watchtower"})
	if err != nil {
		return func() error { return nil }, "", fmt.Errorf("could not start resource: %w", err)
	}

	c := func() error {
		return cleanupDockerResource(pool, resource)
	}

	url := fmt.Sprintf("postgres://postgres:secret@localhost:%s?sslmode=disable", resource.GetPort("5432/tcp"))

	if err := pool.Retry(func() error {
		db, err := sql.Open("postgres", url)
		if err != nil {
			return fmt.Errorf("error opening postgres dev container: %w", err)
		}

		if err := db.Ping(); err != nil {
			return err
		}
		defer db.Close()
		return nil
	}); err != nil {
		return func() error { return nil }, "", fmt.Errorf("could not connect to docker: %w", err)
	}
	return c, url, nil
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
