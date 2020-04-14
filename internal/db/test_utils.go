package db

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead"
	"github.com/jinzhu/gorm"
	"github.com/ory/dockertest/v3"
)

// Need a way to manage the shared database resource for these oplog
// tests, so runningTests gives us a waitgroup to do this and clean up
// the shared database resource when we're done.
var runningTests sync.WaitGroup

func TestConnection(url string) (*gorm.DB, error) {
	return gorm.Open("postgres", url)
}
func TestGormReader(url string) (Reader, error) {
	conn, err := gorm.Open("postgres", url)
	if err != nil {
		return nil, err
	}
	return &GormReadWriter{Tx: conn}, nil
}

// startTest signals that we're starting a test that uses the shared test resources
func StartTest() {
	runningTests.Add(1)
}

// completeTest signals that we've finished a test that uses the shared test resources
func CompleteTest() {
	runningTests.Done()
}

// setup the tests (initialize the database one-time and intialized testDatabaseURL)
func SetupTest(t *testing.T, migrationsDirectory string) (func(), string) {
	if _, err := os.Stat(migrationsDirectory); os.IsNotExist(err) {
		panic("error migrationsDirectory does not exist")
	}

	cleanup := func() {}
	var url string
	var err error
	testInitDatabase.Do(func() {
		cleanup, url, err = initDbInDocker(t, migrationsDirectory)
		if err != nil {
			panic(err)
		}
		testDatabaseURL = url
		db, err := TestConnection(url)
		if err != nil {
			panic(err)
		}
		defer db.Close()
	})
	return cleanup, testDatabaseURL
}

// InitTestWrapper initializes an AEAD wrapping.Wrapper for testing the oplog
func InitTestWrapper(t *testing.T) wrapping.Wrapper {
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

// waitForTests will wait for all the tests that are sharing resources like the database
func waitForTests() {
	runningTests.Wait()
}

// testDatabaseURL is initialized once using sync.Once and set to the database URL for testing
var testDatabaseURL string

// testInitDatabase ensures that the database is only initialized once during the tests.
var testInitDatabase sync.Once

// initDbInDocker initializes postgres within dockertest for the unit tests
func initDbInDocker(t *testing.T, migrationsDirectory string) (cleanup func(), retURL string, err error) {
	if os.Getenv("PG_URL") != "" {
		InitTestStore(t, func() {}, os.Getenv("PG_URL"), migrationsDirectory)
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
	InitTestStore(t, c, url, migrationsDirectory)
	return c, url, nil
}

// InitTestStore will execute the migrations needed to initialize the store for tests
func InitTestStore(t *testing.T, cleanup func(), url string, migrationsDirectory string) {
	// run migrations
	m, err := migrate.New(fmt.Sprintf("file://%s", migrationsDirectory), url)
	if err != nil {
		CompleteTest()
		cleanup()
		t.Fatalf("Error creating migrations: %s", err)
	}
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		CompleteTest()
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
