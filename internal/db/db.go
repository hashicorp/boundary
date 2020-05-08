package db

import (
	"errors"
	"fmt"
	"os"

	"github.com/golang-migrate/migrate/v4"
	"github.com/jinzhu/gorm"
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
