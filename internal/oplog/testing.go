package oplog

import (
	"context"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/oplog/oplog_test"
	"github.com/hashicorp/boundary/testing/dbtest"
	"github.com/hashicorp/go-dbw"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// setup the tests (initialize the database one-time and intialized testDatabaseURL)
func setup(t *testing.T) (func() error, *dbw.DB) {
	t.Helper()
	require := require.New(t)
	cleanup, url, err := testInitDbInDocker(t)
	require.NoError(err)
	db, err := testOpen("postgres", url)
	require.NoError(err)
	oplog_test.Init(t, db)
	t.Cleanup(func() {
		require.NoError(db.Close(context.Background()))
	})
	return cleanup, db
}

func testOpen(dbType string, connectionUrl string) (*dbw.DB, error) {
	var dialect gorm.Dialector
	switch dbType {
	case "postgres":
		dialect = postgres.New(postgres.Config{
			DSN: connectionUrl,
		},
		)
	default:
		return nil, fmt.Errorf("unable to open %s database type", dbType)
	}
	db, err := dbw.OpenWith(dialect)
	if err != nil {
		return nil, fmt.Errorf("unable to open database: %w", err)
	}
	return db, nil
}
func testCleanup(t *testing.T, cleanupFunc func() error, db *dbw.DB) {
	t.Helper()
	err := cleanupFunc()
	assert.NoError(t, err)
	assert.NoError(t, db.Close(context.Background()))
}

func testUser(t *testing.T, db *dbw.DB, name, phoneNumber, email string) *oplog_test.TestUser {
	t.Helper()
	u := &oplog_test.TestUser{
		Name:        name,
		PhoneNumber: phoneNumber,
		Email:       email,
	}
	require.NoError(t, dbw.New(db).Create(context.Background(), u))
	return u
}

func testFindUser(t *testing.T, db *dbw.DB, userId uint32) *oplog_test.TestUser {
	t.Helper()
	var foundUser oplog_test.TestUser
	require.NoError(t, dbw.New(db).LookupWhere(context.Background(), &foundUser, "id = ?", []interface{}{userId}))
	return &foundUser
}

func testId(t *testing.T) string {
	t.Helper()
	id, err := dbw.NewId("i")
	require.NoError(t, err)
	return id
}

func testInitDbInDocker(t *testing.T) (cleanup func() error, retURL string, err error) {
	t.Helper()

	cleanup, retURL, _, err = dbtest.StartUsingTemplate(dbtest.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	testInitStore(t, cleanup, retURL)
	return
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
func testInitStore(t *testing.T, cleanup func() error, url string) {
	t.Helper()
	ctx := context.Background()
	dialect := "postgres"

	d, err := common.SqlOpen(dialect, url)
	require.NoError(t, err)
	sm, err := schema.NewManager(ctx, schema.Dialect(dialect), d)
	require.NoError(t, err)
	require.NoError(t, sm.ApplyMigrations(ctx))
}
