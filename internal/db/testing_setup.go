package db

import (
	"database/sql"
	"fmt"
	"math"
	"math/rand"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/hashicorp/watchtower/internal/db/migrations"
	"github.com/jinzhu/gorm"
	"github.com/ory/dockertest"
)

// TestSetup initializes the database. It returns a cleanup function, a
// gorm db, and the url of the database.
func TestSetup(t *testing.T, dialect string) (cleanup func(), db *gorm.DB, dbUrl string) {
	// t.Helper()
	if dialect != "postgres" {
		t.Fatalf("unknown dialect %q", dialect)
	}

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

	targetDb := strings.ToLower(t.Name())

	if os.Getenv("PG_URL") != "" && os.Getenv("PG_TEMPLATE") != "" {
		templateDb := os.Getenv("PG_TEMPLATE")
		u.Path = "postgres"
		t.Logf("dbUrl: %s", u.String())
		cleanupStack = append(cleanupStack, createDatabase(t, u.String(), targetDb, templateDb, false))

		u.Path = targetDb
	} else {

		templateDb := "template1"
		// connect to the default database and create the test database
		u.Path = "postgres"
		cleanupStack = append(cleanupStack, createDatabase(t, u.String(), targetDb, templateDb, false))

		// connect to the target database and run the migrations
		u.Path = targetDb
		runMigrations(t, u.String())
	}
	dbUrl = u.String()

	db, err = gorm.Open("postgres", dbUrl)
	if err != nil {
		t.Fatal(err)
	}

	return
}

func createDatabase(t *testing.T, dbUrl string, name string, from string, isTemplate bool) (cleanup func()) {
	// t.Helper()

	const (
		dbExists        = ` select count(datname) from pg_database where datname = $1 ; `
		connectionCount = ` select sum(numbackends) from pg_stat_database where datname = $1 ; `

		createDb           = ` create database %s template %s is_template %t ; `
		dropDb             = ` drop database if exists %s ; `
		alterTemplateDb    = ` alter database %s is_template false ; `
		preventConnections = ` alter database %s connection limit 0 ; `
		closeConnections   = ` select pg_terminate_backend(pid) from pg_stat_activity where datname = '%s' ; `
	)

	cleanup = func() {}

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
	{

		r := rand.Float64()
		attempts := 0
		for {
			attempts++
			if _, err := db.Exec(createStatement); err != nil {
				t.Logf("sql: %q failed: %v", createStatement, err)
				if attempts > 100 {
					t.Fatalf("create database %s failed", name)
					break
				}
				t.Logf("create database %s: attempt %d", name, attempts)
				time.Sleep(time.Millisecond * time.Duration(math.Exp2(float64(attempts))*5*(r+0.5)))
			} else {
				break
			}
		}
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

		r := rand.Float64()
		attempts := 0
		var connections int
		for {
			attempts++
			if err := db.QueryRow(connectionCount, name).Scan(&connections); err != nil {
				t.Fatalf("drop database %s: attempt %d: could not query number of connections: %v", name, attempts, err)
			}
			if connections == 0 || attempts > 10 {
				break
			}
			t.Logf("drop database %s: attempt %d", name, attempts)
			time.Sleep(time.Millisecond * time.Duration(math.Exp2(float64(attempts))*5*(r+0.5)))
		}

		if isTemplate {
			alterTemplateDbQuery := fmt.Sprintf(alterTemplateDb, name)
			if _, err := db.Exec(alterTemplateDbQuery); err != nil {
				t.Errorf("sql: %q failed: %v", alterTemplateDbQuery, err)
			}
		}

		preventConnectionsQuery := fmt.Sprintf(preventConnections, name)
		if _, err := db.Exec(preventConnectionsQuery); err != nil {
			t.Errorf("sql: %q failed: %v", preventConnectionsQuery, err)
		}

		closeConnectionsQuery := fmt.Sprintf(closeConnections, name)
		if _, err := db.Exec(closeConnectionsQuery); err != nil {
			t.Errorf("sql: %q failed: %v", closeConnectionsQuery, err)
		}

		dropDbQuery := fmt.Sprintf(dropDb, name)
		if _, err := db.Exec(dropDbQuery); err != nil {
			t.Errorf("sql: %q failed: %v", dropDbQuery, err)
		}
	}

	return
}

func getDatabaseServer(t *testing.T) (cleanup func(), url string) {
	// t.Helper()

	if os.Getenv("PG_URL") != "" {
		url = os.Getenv("PG_URL")
		cleanup = func() {}
		return
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("could not connect to docker: %v", err)
	}

	resource, err := pool.Run("postgres", "latest", []string{"POSTGRES_PASSWORD=secret", "POSTGRES_DB=wt_test"})
	if err != nil {
		t.Fatalf("could not start docker resource: %v", err)
	}

	cleanup = func() {
		if err := cleanupDockerResource(pool, resource); err != nil {
			t.Fatalf("unexpected error in dockertest cleanup: %v", err)
		}
	}

	url = fmt.Sprintf("postgres://postgres:secret@localhost:%s/wt_test?sslmode=disable", resource.GetPort("5432/tcp"))

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
	// t.Helper()
	source, err := migrations.NewMigrationSource("postgres")
	if err != nil {
		t.Fatalf("error creating migration driver: %v", err)
	}
	m, err := migrate.NewWithSourceInstance("httpfs", source, url)
	if err != nil {
		t.Fatalf("error creating migrations: %v", err)
	}
	defer func() {
		if _, err := m.Close(); err != nil {
			t.Fatalf("error closing db connection for migrations: %v", err)
		}
	}()

	{
		r := rand.Float64()
		attempts := 0
		for {
			attempts++
			if err := m.Up(); err != nil && err != migrate.ErrNoChange {
				if attempts > 100 {
					t.Fatalf("migrations failed")
					break
				}
				t.Logf("migration attempt %d failed: %v", attempts, err)
				time.Sleep(time.Millisecond * time.Duration(math.Exp2(float64(attempts))*5*(r+0.5)))
			} else {
				t.Logf("migration attempt %d succeeded", attempts)
				break
			}
		}
	}
}
