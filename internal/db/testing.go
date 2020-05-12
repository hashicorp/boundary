package db

import (
	"crypto/rand"
	"testing"

	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead"
	"github.com/jinzhu/gorm"
)

// setup the tests (initialize the database one-time and intialized testDatabaseURL)
func TestSetup(t *testing.T, dialect string) (func() error, *gorm.DB, string) {
	cleanup := func() error { return nil }
	var url string
	var err error
	cleanup, url, err = InitDbInDocker(dialect)
	if err != nil {
		t.Fatal(err)
	}
	db, err := gorm.Open(dialect, url)
	if err != nil {
		t.Fatal(err)
	}
	return cleanup, db, url
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

