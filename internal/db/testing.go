package db

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/oplog/store"
	"github.com/hashicorp/boundary/testing/dbtest"
	"github.com/hashicorp/go-dbw"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	aead "github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	pgDriver "gorm.io/driver/postgres"
)

// setup the tests (initialize the database one-time and intialized
// testDatabaseURL). Do not close the returned db. Supported options:
// WithTestLogLevel, WithTestDatabaseUrl
func TestSetup(t testing.TB, dialect string, opt ...TestOption) (*DB, string) {
	t.Helper()
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
	db, err := Open(ctx, dbType, url)
	if err != nil {
		t.Fatal(err)
	}
	switch {
	case opts.withLogLevel != DefaultTestLogLevel:
		db.wrapped.LogLevel(dbw.LogLevel(opts.withLogLevel))
	default:
		var defaultLevel dbw.LogLevel
		switch strings.ToLower(os.Getenv("DEFAULT_TEST_LOG_LEVEL")) {
		case "silent":
			defaultLevel = dbw.Silent
		case "error":
			defaultLevel = dbw.Error
		case "warn":
			defaultLevel = dbw.Warn
		case "info":
			defaultLevel = dbw.Info
		default:
			defaultLevel = dbw.Silent
		}
		db.wrapped.LogLevel(defaultLevel)
	}
	t.Cleanup(func() {
		sqlDB, err := db.SqlDB(ctx)
		assert.NoError(t, err)
		assert.NoError(t, sqlDB.Close(), "Got error closing gorm db.")
	})
	return db, url
}

// TestSetupWithMock will return a test DB and an associated Sqlmock which can
// be used to mock out the db responses.
func TestSetupWithMock(t *testing.T) (*DB, sqlmock.Sqlmock) {
	t.Helper()
	require := require.New(t)
	db, mock, err := sqlmock.New()
	require.NoError(err)
	require.NoError(err)
	dbw, err := dbw.OpenWith(pgDriver.New(pgDriver.Config{
		Conn: db,
	}))
	require.NoError(err)
	return &DB{
		wrapped: dbw,
	}, mock
}

// TestWrapper initializes an AEAD wrapping.Wrapper for testing the oplog
func TestWrapper(t testing.TB) wrapping.Wrapper {
	t.Helper()
	rootKey := make([]byte, 32)
	n, err := rand.Read(rootKey)
	if err != nil {
		t.Fatal(err)
	}
	if n != 32 {
		t.Fatal(n)
	}
	root := aead.NewWrapper()
	_, err = root.SetConfig(context.Background(), wrapping.WithKeyId(base64.StdEncoding.EncodeToString(rootKey)))
	if err != nil {
		t.Fatal(err)
	}
	if err := root.SetAesGcmKeyBytes(rootKey); err != nil {
		t.Fatal(err)
	}
	return root
}

// AssertPublicId is a test helper that asserts that the provided id is in
// the format of a public id.
func AssertPublicId(t testing.TB, prefix, actual string) {
	t.Helper()
	assert.NotEmpty(t, actual)
	parts := strings.Split(actual, "_")
	assert.Equalf(t, 2, len(parts), "want one '_' in PublicId, got multiple in %q", actual)
	assert.Equalf(t, prefix, parts[0], "PublicId want prefix: %q, got: %q in %q", prefix, parts[0], actual)
}

// TestDeleteWhere allows you to easily delete resources for testing purposes
// including all the current resources.
func TestDeleteWhere(t testing.TB, conn *DB, i interface{}, whereClause string, args ...interface{}) {
	t.Helper()
	require := require.New(t)
	ctx := context.Background()
	tabler, ok := i.(interface {
		TableName() string
	})
	require.True(ok)
	_, err := dbw.New(conn.wrapped).Exec(ctx, fmt.Sprintf(`delete from "%s" where %s`, tabler.TableName(), whereClause), []interface{}{args})
	require.NoError(err)
}

// TestVerifyOplog will verify that there is an oplog entry that matches the provided resourceId.
// By default it matches the provided resourceId against the `resource-public-id` tag.  If the
// WithResourcePrivateId option is provided, the lookup will use the `resource-private-id` tag.
// An error is returned if the entry or it's metadata is not found.  Returning an error
// allows clients to test if an entry was not written, which is a valid use case.
func TestVerifyOplog(t testing.TB, r Reader, resourceId string, opt ...TestOption) error {
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
	if err := r.LookupWhere(context.Background(), &metadata, where, whereArgs); err != nil {
		return err
	}

	var foundEntry oplog.Entry
	if err := r.LookupWhere(context.Background(), &foundEntry, "id = ?", []interface{}{metadata.EntryId}); err != nil {
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
	withLogLevel          TestLogLevel
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

// TestLogLevel defines a test log level for the underlying db package (if applicable)
type TestLogLevel int

const (
	// See WithTestLogLevel(...) test only option
	DefaultTestLogLevel TestLogLevel = iota
	SilentTestLogLevel
	ErrorTestLogLevel
	WarnTestLogLevel
	InfoTestLogLevel
)

// WithTestLogLevel provides a way to specify a test log level for the
// underlying database package (if applicable).
func WithTestLogLevel(_ testing.TB, l TestLogLevel) TestOption {
	return func(o *testOptions) {
		o.withLogLevel = l
	}
}

// TestCreateTables will create the test tables for the db pkg
func TestCreateTables(t testing.TB, conn *DB) {
	t.Helper()
	t.Cleanup(func() { testDropTables(t, conn) })
	require := require.New(t)
	testCtx := context.Background()
	rw := New(conn)
	_, err := rw.Exec(testCtx, testQueryCreateTables, nil)
	require.NoError(err)
	_, err = rw.Exec(testCtx, testQueryAddOplogEntries, nil)
	require.NoError(err)
}

func testDropTables(t testing.TB, conn *DB) {
	t.Helper()
	require := require.New(t)
	testCtx := context.Background()
	rw := New(conn)
	_, err := rw.Exec(testCtx, testQueryDropTables, nil)
	require.NoError(err)
	_, err = rw.Exec(testCtx, testQueryDeleteOplogEntries, nil)
	require.NoError(err)
}

const (
	testQueryCreateTables = `	
begin;

-- create test tables used in the unit tests for the internal/db package 
-- these tables (db_test_user, db_test_car, db_test_rental, db_test_scooter) are
-- not part of the boundary domain model... they are simply used for testing
-- the internal/db package 
create table if not exists db_test_user (
  id bigint generated always as identity primary key,
  create_time wt_timestamp,
  update_time wt_timestamp,
  public_id text not null unique,
  name text unique,
  phone_number text,
  email text,
  version wt_version
);

create trigger 
  update_time_column 
before 
update on db_test_user 
  for each row execute procedure update_time_column();

-- define the immutable fields for db_test_user
create trigger 
  immutable_columns
before
update on db_test_user
  for each row execute procedure immutable_columns('create_time');

create trigger 
  default_create_time_column
before
insert on db_test_user 
  for each row execute procedure default_create_time();

create trigger 
  update_version_column
after update on db_test_user
  for each row execute procedure update_version_column();
  
create table if not exists db_test_car (
  id bigint generated always as identity primary key,
  create_time wt_timestamp,
  update_time wt_timestamp,
  public_id text not null unique,
  name text unique,
  model text,
  mpg smallint
);

create trigger 
  update_time_column 
before 
update on db_test_car 
  for each row execute procedure update_time_column();

-- define the immutable fields for db_test_car
create trigger 
  immutable_columns
before
update on db_test_car
  for each row execute procedure immutable_columns('create_time');

create trigger 
  default_create_time_column
before
insert on db_test_car
  for each row execute procedure default_create_time();

create table if not exists db_test_rental (
  id bigint generated always as identity primary key,
  create_time wt_timestamp,
  update_time wt_timestamp,
  public_id text not null unique,
  name text unique,
  user_id bigint not null references db_test_user(id),
  car_id bigint not null references db_test_car(id)
);

create trigger 
  update_time_column 
before 
update on db_test_rental 
  for each row execute procedure update_time_column();

-- define the immutable fields for db_test_rental
create trigger 
  immutable_columns
before
update on db_test_rental
  for each row execute procedure immutable_columns('create_time');

create trigger 
  default_create_time_column
before
insert on db_test_rental
  for each row execute procedure default_create_time();


create table if not exists db_test_scooter (
  id bigint generated always as identity primary key,
  create_time wt_timestamp,
  update_time wt_timestamp,
  private_id text not null unique,
  name text unique,
  model text,
  mpg smallint
);

create trigger 
  update_time_column 
before 
update on db_test_scooter 
  for each row execute procedure update_time_column();


-- define the immutable fields for db_test_scooter
create trigger 
  immutable_columns
before
update on db_test_scooter
  for each row execute procedure immutable_columns('create_time');

create trigger 
  default_create_time_column
before
insert on db_test_scooter
  for each row execute procedure default_create_time();

create table if not exists db_test_accessory (
  accessory_id bigint generated always as identity primary key,
  create_time wt_timestamp,
  update_time wt_timestamp,
  description text not null
);

create trigger 
  update_time_column 
before 
update on db_test_accessory 
  for each row execute procedure update_time_column();
  
create trigger 
  immutable_columns
before
update on db_test_accessory
  for each row execute procedure immutable_columns('create_time');
  
create trigger 
  default_create_time_column
before
insert on db_test_accessory
  for each row execute procedure default_create_time();
  
  
create table if not exists db_test_scooter_accessory (
  accessory_id bigint references db_test_accessory(accessory_id),
  scooter_id bigint references db_test_scooter(id),
  create_time wt_timestamp,
  update_time wt_timestamp,
  review text,
  primary key(accessory_id, scooter_id)
);
  
create trigger 
  update_time_column 
before 
update on db_test_scooter_accessory 
  for each row execute procedure update_time_column();
  
create trigger 
  immutable_columns
before
update on db_test_scooter_accessory
  for each row execute procedure immutable_columns('create_time');

create trigger 
  default_create_time_column
before
insert on db_test_scooter_accessory
  for each row execute procedure default_create_time();
  
commit;
`
	testQueryDropTables = `
begin;
drop table if exists db_test_user cascade;
drop table if exists db_test_car cascade;
drop table if exists db_test_rental cascade;
drop table if exists db_test_scooter cascade;
drop table if exists db_test_accessory cascade;
drop table if exists db_test_scooter_accessory cascade;
commit;
`

	testQueryAddOplogEntries = `
begin;

insert into oplog_ticket (name, version)
values
  ('db_test_user', 1),
  ('db_test_car', 1),
  ('db_test_rental', 1),
  ('db_test_scooter', 1),
  ('db_test_accessory', 1),
  ('db_test_scooter_accessory', 1);
commit;
`
	testQueryDeleteOplogEntries = `
begin;

delete from oplog_ticket where name in
(
  'db_test_user',
  'db_test_car',
  'db_test_rental',
  'db_test_scooter',
  'db_test_accessory',
  'db_test_scooter_accessory'
);

commit;
`
)
