package iam

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jinzhu/gorm"
	"github.com/ory/dockertest/v3"
)

// Need a way to manage the shared database resource for these oplog
// tests, so runningTests gives us a waitgroup to do this and clean up
// the shared database resource when we're done.
var runningTests sync.WaitGroup

// startTest signals that we're starting a test that uses the shared test resources
func startTest() {
	runningTests.Add(1)
}

// completeTest signals that we've finished a test that uses the shared test resources
func completeTest() {
	runningTests.Done()
}

// waitForTests will wait for all the tests that are sharing resources like the database
func waitForTests() {
	runningTests.Wait()
}

// testDatabaseURL is initialized once using sync.Once and set to the database URL for testing
var testDatabaseURL string

// testInitDatabase ensures that the database is only initialized once during the tests.
var testInitDatabase sync.Once

// setup the tests (initialize the database one-time and intialized testDatabaseURL)
func setup(t *testing.T) (func(), string) {
	cleanup := func() {}
	var url string
	var err error
	testInitDatabase.Do(func() {
		cleanup, url, err = initDbInDocker(t)
		if err != nil {
			panic(err)
		}
		testDatabaseURL = url
		db, err := test_dbconn(url)
		if err != nil {
			panic(err)
		}
		defer db.Close()
	})
	return cleanup, testDatabaseURL
}

// initDbInDocker initializes postgres within dockertest for the unit tests
func initDbInDocker(t *testing.T) (cleanup func(), retURL string, err error) {
	if os.Getenv("PG_URL") != "" {
		initTestStore(t, func() {}, os.Getenv("PG_URL"))
		return func() {}, os.Getenv("PG_URL"), nil
	}
	pool, err := dockertest.NewPool("")
	if err != nil {
		return func() {}, "", fmt.Errorf("could not connect to docker: %w", err)
	}

	resource, err := pool.Run("postgres", "latest", []string{"POSTGRES_PASSWORD=secret", "POSTGRES_DB=watchtower"})
	if err != nil {
		return func() {}, "", fmt.Errorf("could not start resource: %w", err)
	}

	c := func() {
		cleanupResource(t, pool, resource)
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
		return func() {}, "", fmt.Errorf("could not connect to docker: %w", err)
	}
	initTestStore(t, c, url)
	return c, url, nil
}

// initTestStore will execute the migrations needed to initialize the store for tests
func initTestStore(t *testing.T, cleanup func(), url string) {
	// run migrations
	m, err := migrate.New("file://migrations/postgres", url)
	if err != nil {
		cleanup()
		t.Fatalf("Error creating migrations: %s", err)
	}
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		cleanup()
		t.Fatalf("Error running migrations: %s", err)
	}
}

// cleanupResource will clean up the dockertest resources (postgres)
func cleanupResource(t *testing.T, pool *dockertest.Pool, resource *dockertest.Resource) {
	waitForTests()
	var err error
	for i := 0; i < 10; i++ {
		err = pool.Purge(resource)
		if err == nil {
			return
		}
	}

	if strings.Contains(err.Error(), "No such container") {
		return
	}
	t.Fatalf("Failed to cleanup local container: %s", err)
}

func test_dbconn(url string) (*gorm.DB, error) {
	return gorm.Open("postgres", url)
}
