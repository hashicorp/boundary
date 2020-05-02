package database

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/ory/dockertest/v3"
)

func cleanupResource(t *testing.T, pool *dockertest.Pool, resource *dockertest.Resource) {
	var err error
	for i := 0; i < 10; i++ {
		err = pool.Purge(resource)
		if err == nil {
			return
		}
		time.Sleep(1 * time.Second)
	}

	if strings.Contains(err.Error(), "No such container") {
		return
	}
	t.Fatalf("Failed to cleanup local container: %s", err)
}

func newPostgresTestContainer(t *testing.T) (cleanup func(), retURL string) {
	if os.Getenv("PG_URL") != "" {
		return func() {}, os.Getenv("PG_URL")
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("Failed to connect to docker: %s", err)
	}

	resource, err := pool.Run("postgres", "latest", []string{"POSTGRES_PASSWORD=secret", "POSTGRES_DB=database"})
	if err != nil {
		t.Fatalf("Could not start local PostgreSQL docker container: %s", err)
	}

	cleanup = func() {
		cleanupResource(t, pool, resource)
	}

	retURL = fmt.Sprintf("postgres://postgres:secret@localhost:%s/database?sslmode=disable", resource.GetPort("5432/tcp"))

	// exponential backoff-retry
	if err = pool.Retry(func() error {
		var err error
		var db *sql.DB
		db, err = sql.Open("postgres", retURL)
		if err != nil {
			return err
		}
		defer db.Close()
		return db.Ping()
	}); err != nil {
		cleanup()
		t.Fatalf("Could not connect to PostgreSQL docker container: %s", err)
	}

	return
}
func PreparePostgresTestContainer(t *testing.T) (cleanup func(), retURL string) {
	cleanup, retURL = newPostgresTestContainer(t)
	// run migrations
	m, err := migrate.New("file://migrations/postgresql", retURL)
	if err != nil {
		cleanup()
		t.Fatalf("Error creating migrations: %s", err)
	}
	if err := m.Up(); err != nil {
		cleanup()
		t.Fatalf("Error running migrations: %s", err)
	}
	return
}

func TestPostgreSQL_Setup(t *testing.T) {
	// cleanup, connURL := preparePostgresTestContainer(t)
	// defer cleanup()

	// _, connURL := preparePostgresTestContainer(t)
	// fmt.Println(connURL)

}
