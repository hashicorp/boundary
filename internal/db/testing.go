package db

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/oplog/store"
	"github.com/hashicorp/boundary/testing/dbtest"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm/logger"
)

// setup the tests (initialize the database one-time and intialized testDatabaseURL). Do not close the returned db.
func TestSetup(t *testing.T, dialect string, opt ...TestOption) (*DB, string) {
	var cleanup func() error
	var url string
	var err error
	ctx := context.Background()

	opts := getTestOpts(opt...)

	switch opts.withTestDatabaseUrl {
	case "":
		cleanup, url, _, err = dbtest.StartUsingTemplate(dialect, dbtest.WithTemplate(opts.withTemplate))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			assert.NoError(t, cleanup(), "Got error cleaning up db in docker.")
		})
	default:
		url = opts.withTestDatabaseUrl
	}

	_, err = schema.MigrateStore(ctx, schema.Dialect(dialect), url)
	if err != nil {
		t.Fatalf("Couldn't init store on existing db: %v", err)
	}
	dbType, err := StringToDbType(dialect)
	if err != nil {
		t.Fatal(err)
	}
	db, err := Open(dbType, url)
	if err != nil {
		t.Fatal(err)
	}
	db.Logger.LogMode(logger.Error)
	t.Cleanup(func() {
		sqlDB, err := db.SqlDB(ctx)
		assert.NoError(t, err)
		assert.NoError(t, sqlDB.Close(), "Got error closing gorm db.")
	})
	return db, url
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
	_, err = root.SetConfig(map[string]string{
		"key_id": base64.StdEncoding.EncodeToString(rootKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := root.SetAESGCMKeyBytes(rootKey); err != nil {
		t.Fatal(err)
	}
	return root
}

// AssertPublicId is a test helper that asserts that the provided id is in
// the format of a public id.
func AssertPublicId(t *testing.T, prefix, actual string) {
	t.Helper()
	assert.NotEmpty(t, actual)
	parts := strings.Split(actual, "_")
	assert.Equalf(t, 2, len(parts), "want one '_' in PublicId, got multiple in %q", actual)
	assert.Equalf(t, prefix, parts[0], "PublicId want prefix: %q, got: %q in %q", prefix, parts[0], actual)
}

// TestVerifyOplog will verify that there is an oplog entry that matches the provided resourceId.
// By default it matches the provided resourceId against the `resource-public-id` tag.  If the
// WithResourcePrivateId option is provided, the lookup will use the `resource-private-id` tag.
// An error is returned if the entry or it's metadata is not found.  Returning an error
// allows clients to test if an entry was not written, which is a valid use case.
func TestVerifyOplog(t *testing.T, r Reader, resourceId string, opt ...TestOption) error {
	t.Helper()

	// sql where clauses
	const (
		whereBase = `
      key = ?
and value = ?
`

		whereOptype = `
and entry_id in (
  select entry_id
    from oplog_metadata
	 where key = 'op-type'
     and value = ?
)
`
		whereCreateNotBefore = `
and create_time > NOW()::timestamp - (interval '1 second' * ?)
`
	)

	opts := getTestOpts(opt...)
	withOperation := opts.withOperation
	withCreateNotBefore := opts.withCreateNotBefore

	whereKey := "resource-public-id"
	if opts.withResourcePrivateId {
		whereKey = "resource-private-id"
	}

	where := whereBase
	whereArgs := []interface{}{
		whereKey,
		resourceId,
	}

	if withOperation != oplog.OpType_OP_TYPE_UNSPECIFIED {
		where = where + whereOptype
		whereArgs = append(whereArgs, withOperation.String())
	}

	if withCreateNotBefore != nil {
		where = where + whereCreateNotBefore
		whereArgs = append(whereArgs, int(*withCreateNotBefore))
	}

	var metadata store.Metadata
	if err := r.LookupWhere(context.Background(), &metadata, where, whereArgs...); err != nil {
		return err
	}

	var foundEntry oplog.Entry
	if err := r.LookupWhere(context.Background(), &foundEntry, "id = ?", metadata.EntryId); err != nil {
		return err
	}
	return nil
}

// getTestOpts - iterate the inbound TestOptions and return a struct
func getTestOpts(opt ...TestOption) testOptions {
	opts := getDefaultTestOptions()
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

// TestOption - how Options are passed as arguments
type TestOption func(*testOptions)

// options = how options are represented
type testOptions struct {
	withCreateNotBefore   *int
	withOperation         oplog.OpType
	withTestDatabaseUrl   string
	withResourcePrivateId bool
	withTemplate          string
}

func getDefaultTestOptions() testOptions {
	return testOptions{
		withCreateNotBefore: nil,
		withOperation:       oplog.OpType_OP_TYPE_UNSPECIFIED,
	}
}

// WithCreateNotBefore provides an option to specify that the create time is not
// before (nbf) N seconds
func WithCreateNotBefore(nbfDuration time.Duration) TestOption {
	return func(o *testOptions) {
		secs := int(nbfDuration.Truncate(time.Second).Seconds())
		o.withCreateNotBefore = &secs
	}
}

// WithOperation provides an option to specify the operation type
func WithOperation(op oplog.OpType) TestOption {
	return func(o *testOptions) {
		o.withOperation = op
	}
}

// WithTestDatabaseUrl provides a way to specify an existing database for tests
func WithTestDatabaseUrl(url string) TestOption {
	return func(o *testOptions) {
		o.withTestDatabaseUrl = url
	}
}

// WithResourcePrivateId provides a way to specify that the resource lookup action
// uses `resource-private-id` tag instead of the default `resource-public-id` tag
func WithResourcePrivateId(enable bool) TestOption {
	return func(o *testOptions) {
		o.withResourcePrivateId = enable
	}
}

// WithTemplate provides a way to specify the source database template for creating
// a database.
func WithTemplate(template string) TestOption {
	return func(o *testOptions) {
		o.withTemplate = template
	}
}
