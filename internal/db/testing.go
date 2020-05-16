package db

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead"
	"github.com/hashicorp/watchtower/internal/db/migrations"
	"github.com/jinzhu/gorm"
	"github.com/ory/dockertest"
)

// TestSetup initializes the database. It returns a cleanup function, a
// gorm db, and the url of the database.
func TestSetup(t *testing.T, dialect string) (cleanup func(), db *gorm.DB, dbUrl string) {
	if dialect != "postgres" {
		t.Fatalf("unknown dialect %q", dialect)
	}

	// Functions called from this function should never call t.Fatal.
	// Calling t.Fatal
	// If
	// any of those functions call t.Fatal, it would prevent
	// Those
	// function should use t.Error.
	var cleanupStack []func()
	cleanup = func() {
		for i := len(cleanupStack) - 1; i >= 0; i-- {
			cleanupStack[i]()
		}
	}

	defer func() {
		if t.Failed() {
			cleanup()
		}
	}()

	dbServerCleanup, dbUrl := getDatabaseServer(t)
	cleanupStack = append(cleanupStack, dbServerCleanup)

	u, err := url.Parse(dbUrl)
	if err != nil {
		t.Fatalf("could not parse postgres url %s: %s", dbUrl, err)
	}

	templateDb := "wt_template"

	// connect to the default database and create the template database
	u.Path = ""
	cleanupStack = append(cleanupStack, createDatabase(t, u.String(), templateDb, "template1", true))

	// connect to the template database and run the migrations
	u.Path = templateDb
	runMigrations(t, u.String())

	// connect to the default database and create the test database
	u.Path = ""
	cleanupStack = append(cleanupStack, createDatabase(t, u.String(), t.Name(), templateDb, false))

	u.Path = t.Name()
	dbUrl = u.String()

	db, err = gorm.Open("postgres", dbUrl)
	if err != nil {
		t.Fatal(err)
	}

	return
}

func createDatabase(t *testing.T, dbUrl string, name string, from string, isTemplate bool) (cleanup func()) {
	t.Helper()

	const (
		dbExists = `
select count(datname)
  from pg_database
 where datname = $1
; `

		createDb = ` create database %s template %s is_template %t ; `
		dropDb   = ` drop database if exists %s ; `
	)

	cleanup = func() {}

	// This function should not call t.Fatal since that would prevent
	// other functions from being called.

	db, err := sql.Open("postgres", dbUrl)
	if err != nil {
		t.Fatalf("connect to %s failed: %v", dbUrl, err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Fatalf("create database %s: failed to close sql connection %s: %v", name, dbUrl, err)
		}
	}()

	var count int
	if err := db.QueryRow(dbExists, name).Scan(&count); err != nil {
		t.Fatalf("create database %s: could not query if database exists: %v", name, err)
	}

	if count > 0 && isTemplate {
		return
	}

	if count > 0 {
		t.Fatalf("create database %s: database already exists", name)
	}
	createStatement := fmt.Sprintf(createDb, name, from, isTemplate)
	if _, err := db.Exec(createStatement); err != nil {
		// t.Fatalf("create database %s with template %s as template %t at %s failed: %v", name, from, isTemplate, dbUrl, err)
		t.Fatalf("sql: %q failed: %v", createStatement, err)
	}

	cleanup = func() {
		db, err := sql.Open("postgres", dbUrl)
		if err != nil {
			t.Fatalf("drop database %s: connect to %s failed: %v", name, dbUrl, err)
		}
		defer func() {
			if err := db.Close(); err != nil {
				t.Fatalf("drop database %s: failed to close sql connection %s: %v", name, dbUrl, err)
			}
		}()

		dropStatement := fmt.Sprintf(dropDb, name)
		if _, err := db.Exec(dropStatement); err != nil {
			// t.Fatalf("drop database %s at %s failed: %v", name, dbUrl, err)
			t.Fatalf("sql: %q failed: %v", dropStatement, err)
		}
	}

	return
}

func getDatabaseServer(t *testing.T) (cleanup func(), url string) {
	t.Helper()

	if os.Getenv("PG_URL") != "" {
		url = os.Getenv("PG_URL")
		cleanup = func() {}
		return
	}

	// Only this function can call t.Fatal since it is the first and no
	// additional cleanup would need to be done.
	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("could not connect to docker: %v", err)
	}

	resource, err := pool.Run("postgres", "latest", []string{"POSTGRES_PASSWORD=secret", "POSTGRES_DB=watchtower"})
	if err != nil {
		t.Fatalf("could not start docker resource: %v", err)
	}

	// Cleanup functions should not call t.Fatal since that could prevent
	// other cleanup functions from being called.
	cleanup = func() {
		if err := cleanupDockerResource(pool, resource); err != nil {
			t.Fatalf("unexpected error in dockertest cleanup: %v", err)
		}
	}

	url = fmt.Sprintf("postgres://postgres:secret@localhost:%s?sslmode=disable", resource.GetPort("5432/tcp"))

	if err := pool.Retry(func() error {
		db, err := sql.Open("postgres", url)
		if err != nil {
			return err
		}

		if err := db.Ping(); err != nil {
			return err
		}
		defer db.Close()
		return nil
	}); err != nil {
		t.Fatalf("could not connect to docker: %v", err)
	}

	return
}

func runMigrations(t *testing.T, url string) {
	source, err := migrations.NewMigrationSource("postgres")
	if err != nil {
		t.Fatalf("error creating migration driver: %v", err)
	}
	m, err := migrate.NewWithSourceInstance("httpfs", source, url)
	if err != nil {
		t.Fatalf("error creating migrations: %v", err)
	}
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("error running migrations: %v", err)
	}
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
