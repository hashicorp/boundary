package db

import (
	"crypto/rand"
	"fmt"
	"os"
	"testing"

	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead"
	"github.com/jinzhu/gorm"
)

// setup the tests (initialize the database one-time and intialized testDatabaseURL)
func TestSetup(t *testing.T, dialect string) (func() error, *gorm.DB) {
	cleanup := func() error { return nil }
	var url string
	var err error
	cleanup, url, err = initDbInDocker(t, dialect)
	if err != nil {
		t.Fatal(err)
	}
	db, err := gorm.Open(dialect, url)
	if err != nil {
		t.Fatal(err)
	}
	return cleanup, db
}

// TestWrapper initializes an AEAD wrapping.Wrapper for testing the oplog
func TestWrapper(t *testing.T) wrapping.Wrapper {
	rootKey := make([]byte, 32)
	n, err := rand.Read(rootKey)
	if err != nil {
		t.Fatal(err)
	}
	if n != 32 {
		t.Fatal(n)
	}
	root := aead.NewWrapper(nil)
	if err := root.SetAESGCMKeyBytes(rootKey); err != nil {
		t.Fatal(err)
	}
	return root
}

// initDbInDocker initializes postgres within dockertest for the unit tests
func initDbInDocker(t *testing.T, dialect string) (cleanup func() error, retURL string, err error) {
	switch dialect {
	case "postgres":
		if os.Getenv("PG_URL") != "" {
			if err := InitStore(dialect, func() error { return nil }, os.Getenv("PG_URL")); err != nil {
				return func() error { return nil }, os.Getenv("PG_URL"), fmt.Errorf("error initializing store: %w", err)
			}
			return func() error { return nil }, os.Getenv("PG_URL"), nil
		}
	}
	c, url, err := StartDbInDocker(dialect)
	if err != nil {
		return func() error { return nil }, "", fmt.Errorf("could not start docker: %w", err)
	}
	if err := InitStore(dialect, c, url); err != nil {
		return func() error { return nil }, "", fmt.Errorf("error initializing store: %w", err)
	}
	return c, url, nil
}
