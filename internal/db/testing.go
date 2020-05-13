package db

import (
	"context"
	"crypto/rand"
	"fmt"
	"strconv"
	"testing"

	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead"
	"github.com/hashicorp/watchtower/internal/oplog"
	"github.com/hashicorp/watchtower/internal/oplog/store"
	"github.com/jinzhu/gorm"
)

// setup the tests (initialize the database one-time and intialized testDatabaseURL)
func TestSetup(t *testing.T, dialect string) (func() error, *gorm.DB, string) {
	cleanup := func() error { return nil }
	var url string
	var err error
	cleanup, url, err = InitDbInDocker(dialect)
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
func TestVerifyOplog(r Reader, resourcePublicId string, opt ...TestOption) error {
	opts := getTestOpts(opt...)
	withOperation := opts.withOperation
	withCreateNbf := opts.withCreateNbf

	var metadata store.Metadata

	where := "key = 'resource-public-id' and value = ?"
	args := []interface{}{
		resourcePublicId,
	}

	if withOperation != oplog.OpType_OP_TYPE_UNSPECIFIED {
		where = where + ` and entry_id in (
			select entry_id
			FROM oplog_metadata
			where
			 	key = 'op-type' and
				 value = ?
			 )`
		args = append(args, strconv.Itoa(int(withOperation)))
	}

	if withCreateNbf != nil {
		where = fmt.Sprintf("%s and create_time > NOW()::timestamp - interval '%d second'", where, *withCreateNbf)
	}

	if err := r.LookupWhere(context.Background(), &metadata, where, args...); err != nil {
		return err
	}

	var foundEntry oplog.Entry
	if err := r.LookupWhere(
		context.Background(),
		&foundEntry,
		"id = ?",
		metadata.EntryId,
	); err != nil {
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
	withCreateNbf *int
	withOperation oplog.OpType
}

func getDefaultTestOptions() testOptions {
	return testOptions{
		withCreateNbf: nil,
		withOperation: oplog.OpType_OP_TYPE_UNSPECIFIED,
	}
}

// WithCreateNbf provides an option to specify that the create time is not
// before (nbf) N seconds
func WithCreateNbf(secs int) TestOption {
	return func(o *testOptions) {
		o.withCreateNbf = &secs
	}
}

// WithOperation provides an option to specify the operation type
func WithOperation(op oplog.OpType) TestOption {
	return func(o *testOptions) {
		o.withOperation = op
	}
}
