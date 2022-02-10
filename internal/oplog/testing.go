package oplog

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/oplog/oplog_test"
	"github.com/hashicorp/boundary/testing/dbtest"
	"github.com/hashicorp/go-dbw"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	aead "github.com/hashicorp/go-kms-wrapping/wrappers/aead/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
)

// setup the tests (initialize the database one-time and intialized testDatabaseURL)
func setup(t *testing.T) *dbw.DB {
	t.Helper()
	require := require.New(t)
	cleanup, url, err := testInitDbInDocker(t)
	require.NoError(err)
	db := testOpen(t, "postgres", url)
	require.NoError(err)
	oplog_test.Init(t, db)
	t.Cleanup(func() {
		assert.NoError(t, db.Close(context.Background()))
		assert.NoError(t, cleanup())
	})
	return db
}

func testOpen(t *testing.T, dbType string, connectionUrl string) *dbw.DB {
	t.Helper()
	require := require.New(t)
	var dialect dbw.Dialector
	switch dbType {
	case "postgres":
		dialect = postgres.New(postgres.Config{
			DSN: connectionUrl,
		},
		)
	default:
		t.Errorf("unable to open %s database type", dbType)
		t.FailNow()
	}
	db, err := dbw.OpenWith(dialect)
	require.NoError(err)
	return db
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
	require := require.New(t)
	cleanup, retURL, _, err = dbtest.StartUsingTemplate(dbtest.Postgres)
	require.NoError(err)
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
	root := aead.NewWrapper()
	err = root.SetAesGcmKeyBytes(rootKey)
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

type constraintResults struct {
	Name      string
	TableName string
}

func testListConstraints(t *testing.T, db *dbw.DB, tableName string) []constraintResults {
	t.Helper()
	require := require.New(t)
	testCtx := context.Background()
	const constraintSql = `select pgc.conname as name,
	ccu.table_schema as table_schema,
	ccu.table_name,
	ccu.column_name,
	pgc.consrc as definition
from pg_constraint pgc
join pg_namespace nsp on nsp.oid = pgc.connamespace
join pg_class  cls on pgc.conrelid = cls.oid
left join information_schema.constraint_column_usage ccu
	   on pgc.conname = ccu.constraint_name
	   and nsp.nspname = ccu.constraint_schema 
-- where contype ='c'
order by ccu.table_name,pgc.conname `

	rw := dbw.New(db)
	rows, err := rw.Query(testCtx, constraintSql, []interface{}{tableName})
	require.NoError(err)
	type result struct {
		Name      string
		TableName string
	}
	results := []constraintResults{}
	for rows.Next() {
		var r constraintResults
		rw.ScanRows(rows, &r)
		results = append(results, r)
	}
	return results
}
