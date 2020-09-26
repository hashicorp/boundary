package oplog

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	"github.com/hashicorp/boundary/internal/oplog/oplog_test"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead"
	"github.com/hashicorp/go-uuid"
	"github.com/jinzhu/gorm"
	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testCleanup(t *testing.T, cleanupFunc func(), db *gorm.DB) {
	t.Helper()
	cleanupFunc()
	err := db.Close()
	assert.NoError(t, err)
}

func testUser(t *testing.T, db *gorm.DB, name, phoneNumber, email string) *oplog_test.TestUser {
	t.Helper()
	u := &oplog_test.TestUser{
		Name:        name,
		PhoneNumber: phoneNumber,
		Email:       email,
	}
	w := GormWriter{db}

	err := w.Create(&u)
	require.NoError(t, err)
	return u
}

func testFindUser(t *testing.T, db *gorm.DB, userId uint32) *oplog_test.TestUser {
	t.Helper()
	var foundUser oplog_test.TestUser
	err := db.Where("id = ?", userId).First(&foundUser).Error
	require.NoError(t, err)
	return &foundUser
}

func testId(t *testing.T) string {
	t.Helper()
	id, err := uuid.GenerateUUID()
	require.NoError(t, err)
	return id
}

// testInitDbInDocker initializes postgres within dockertest for the unit tests
func testInitDbInDocker(t *testing.T) (cleanup func(), retURL string, err error) {
	t.Helper()
	pool, err := dockertest.NewPool("")
	require.NoErrorf(t, err, "could not connect to docker: %w", err)

	resource, err := pool.Run("postgres", "12", []string{"POSTGRES_PASSWORD=password", "POSTGRES_DB=boundary"})
	require.NoErrorf(t, err, "could not start resource: %w", err)

	c := func() {
		err := testCleanupResource(t, pool, resource)
		assert.NoError(t, err)
	}

	url := fmt.Sprintf("postgres://postgres:password@localhost:%s?sslmode=disable", resource.GetPort("5432/tcp"))

	err = pool.Retry(func() error {
		db, err := sql.Open("postgres", url)
		if err != nil {
			return fmt.Errorf("error opening postgres dev container: %w", err)
		}

		if err := db.Ping(); err != nil {
			return err
		}
		defer db.Close()
		return nil
	})
	require.NoErrorf(t, err, "could not connect to docker: %w", err)
	testInitStore(t, c, url)
	return c, url, nil
}

// testWrapper initializes an AEAD wrapping.Wrapper for testing the oplog
func testWrapper(t *testing.T) wrapping.Wrapper {
	t.Helper()
	rootKey := make([]byte, 32)
	n, err := rand.Read(rootKey)
	require.NoError(t, err)
	require.Equal(t, n, 32)
	root := aead.NewWrapper(nil)
	err = root.SetAESGCMKeyBytes(rootKey)
	require.NoError(t, err)
	return root
}

// testInitStore will execute the migrations needed to initialize the store for tests
func testInitStore(t *testing.T, cleanup func(), url string) {
	t.Helper()
	// run migrations
	m, err := migrate.New("file://../db/migrations/postgres", url)
	require.NoError(t, err, "Error creating migrations")

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		cleanup()
		require.NoError(t, err, "Error running migrations")
	}
}

// testCleanupResource will clean up the dockertest resources (postgres)
func testCleanupResource(t *testing.T, pool *dockertest.Pool, resource *dockertest.Resource) error {
	t.Helper()
	var err error
	for i := 0; i < 10; i++ {
		err = pool.Purge(resource)
		if err == nil {
			return nil
		}
	}
	if strings.Contains(err.Error(), "No such container") {
		return nil
	}
	return fmt.Errorf("Failed to cleanup local container: %s", err)
}
