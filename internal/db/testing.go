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

// TestSetup initializes the database. It returns a cleanup function, a
// gorm db, and the url of the database.
func TestSetup(t *testing.T, dialect string) (cleanup func(), db *gorm.DB, url string) {
	dbCleanup, url, _, err := InitDbInDocker(dialect)
	if err != nil {
		if dbCleanup != nil {
			_ = dbCleanup()
		}
		t.Fatal(err)
	}
	db, err = gorm.Open(dialect, url)
	if err != nil {
		_ = dbCleanup()
		t.Fatal(err)
	}
	cleanup = func() {
		if err := dbCleanup(); err != nil {
			t.Errorf("unexpected error in db cleanup: %v", err)
		}
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
