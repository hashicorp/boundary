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
	"github.com/jinzhu/gorm"
)

// setup the tests (initialize the database one-time and intialized testDatabaseURL)
func TestSetup(t *testing.T, migrationsDirectory string) (func() error, *gorm.DB) {
	if _, err := os.Stat(migrationsDirectory); os.IsNotExist(err) {
		t.Fatal("error migrationsDirectory does not exist")
	}

	cleanup := func() error { return nil }
	var url string
	var err error
	cleanup, url, err = initDbInDocker(t, migrationsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	db, err := gorm.Open("postgres", url)
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
func initDbInDocker(t *testing.T, migrationsDirectory string) (cleanup func() error, retURL string, err error) {
	if os.Getenv("PG_URL") != "" {
		TestInitStore(t, func() error { return nil }, os.Getenv("PG_URL"), migrationsDirectory)
		return func() error { return nil }, os.Getenv("PG_URL"), nil
	}
	c, url, err := StartDbInDocker()
	if err != nil {
		return func() error { return nil }, "", fmt.Errorf("could not start docker: %w", err)
	}
	TestInitStore(t, c, url, migrationsDirectory)
	return c, url, nil
}

// TestInitStore will execute the migrations needed to initialize the store for tests
func TestInitStore(t *testing.T, cleanup func() error, url string, migrationsDirectory string) {
	// run migrations
	m, err := migrate.New(fmt.Sprintf("file://%s", migrationsDirectory), url)
	if err != nil {
		cleanup()
		t.Fatalf("Error creating migrations: %s", err)
	}
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		cleanup()
		t.Fatalf("Error running migrations: %s", err)
	}
}
