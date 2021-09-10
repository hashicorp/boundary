package oplog

import (
	"context"
	"crypto/rand"
	"database/sql"
	"testing"

	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/oplog/oplog_test"
	"github.com/hashicorp/boundary/testing/dbtest"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead"
	"github.com/hashicorp/go-uuid"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testCleanup(t *testing.T, cleanupFunc func() error, db *gorm.DB) {
	t.Helper()
	err := cleanupFunc()
	assert.NoError(t, err)
	err = db.Close()
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

	d, err := sql.Open(dialect, url)
	require.NoError(t, err)
	sm, err := schema.NewManager(ctx, dialect, d)
	require.NoError(t, err)
	require.NoError(t, sm.RollForward(ctx))
}
