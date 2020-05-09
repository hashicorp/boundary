package db

import (
	"crypto/rand"
	"fmt"
	"os"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead"
	"github.com/hashicorp/watchtower/internal/db/migrations"
	"github.com/jinzhu/gorm"
)

// setup the tests (initialize the database one-time and intialized testDatabaseURL)
func TestSetup(t *testing.T, flavor string) (func() error, *gorm.DB) {
	cleanup := func() error { return nil }
	var url string
	var err error
	cleanup, url, err = initDbInDocker(t, flavor)
	if err != nil {
		t.Fatal(err)
	}
	db, err := gorm.Open(flavor, url)
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
func initDbInDocker(t *testing.T, flavor string) (cleanup func() error, retURL string, err error) {
	switch flavor {
	case "postgres":
		if os.Getenv("PG_URL") != "" {
			TestInitStore(t, flavor, func() error { return nil }, os.Getenv("PG_URL"))
			return func() error { return nil }, os.Getenv("PG_URL"), nil
		}
	}
	c, url, err := StartDbInDocker(flavor)
	if err != nil {
		return func() error { return nil }, "", fmt.Errorf("could not start docker: %w", err)
	}
	TestInitStore(t, flavor, c, url)
	return c, url, nil
}

// TestInitStore will execute the migrations needed to initialize the store for tests
func TestInitStore(t *testing.T, flavor string, cleanup func() error, url string) {
	// run migrations
	source, err := migrations.NewMigrationSource(flavor)
	if err != nil {
		cleanup()
		t.Fatalf("Error creating migration driver: %s", err)
	}
	m, err := migrate.NewWithSourceInstance("httpfs", source, url)
	if err != nil {
		cleanup()
		t.Fatalf("Error creating migrations: %s", err)
	}
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		cleanup()
		t.Fatalf("Error running migrations: %s", err)
	}
}
