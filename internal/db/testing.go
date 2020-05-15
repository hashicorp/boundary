package db

import (
	"context"
	"crypto/rand"
	"strconv"
	"testing"
	"time"

	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead"
	"github.com/hashicorp/watchtower/internal/oplog"
	"github.com/hashicorp/watchtower/internal/oplog/store"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
)

// setup the tests (initialize the database one-time and intialized testDatabaseURL)
func TestSetup(t *testing.T, dialect string) (func() error, *gorm.DB, string) {
	cleanup := func() error { return nil }
	var url string
	var err error
	cleanup, url, _, err = InitDbInDocker(dialect)
	if err != nil {
		t.Fatal(err)
	}
	db, err := gorm.Open(dialect, url)
	if err != nil {
		t.Fatal(err)
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

// TestVerifyOplog will verify that there is an oplog entry
func TestVerifyOplog(t *testing.T, r Reader, resourcePublicId string, opt ...TestOption) {
	t.Helper()
	assert := assert.New(t)

	// sql where clauses
	const (
		whereBase = `
      key = 'resource-public-id'
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

	where := whereBase
	whereArgs := []interface{}{
		resourcePublicId,
	}

	if withOperation != oplog.OpType_OP_TYPE_UNSPECIFIED {
		where = where + whereOptype
		whereArgs = append(whereArgs, strconv.Itoa(int(withOperation)))
	}

	if withCreateNotBefore != nil {
		where = where + whereCreateNotBefore
		whereArgs = append(whereArgs, int(*withCreateNotBefore))
	}

	var metadata store.Metadata
	if err := r.LookupWhere(context.Background(), &metadata, where, whereArgs...); err != nil {
		assert.NoError(err)
		return
	}

	var foundEntry oplog.Entry
	if err := r.LookupWhere(context.Background(), &foundEntry, "id = ?", metadata.EntryId); err != nil {
		assert.NoError(err)
		return
	}
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
	withCreateNotBefore *int
	withOperation       oplog.OpType
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

