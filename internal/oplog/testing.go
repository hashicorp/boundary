// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

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
	kms "github.com/hashicorp/go-kms-wrapping/extras/kms/v2"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	aead "github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
)

// TestOplogDeleteAllEntries allows you to delete all the entries for testing.
func TestOplogDeleteAllEntries(t testing.TB, conn *dbw.DB) {
	_, err := dbw.New(conn).Exec(context.Background(), fmt.Sprintf("delete from %q", Entry{}.TableName()), nil)
	require.NoError(t, err)
}

// setup the tests (initialize the database one-time and intialized testDatabaseURL)
func setup(ctx context.Context, t testing.TB) (*dbw.DB, wrapping.Wrapper) {
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
	rootKey := make([]byte, 32)
	n, err := rand.Read(rootKey)
	require.NoError(err)
	require.Equal(n, 32)
	root := aead.NewWrapper()
	root.SetConfig(context.Background(), wrapping.WithKeyId("key_id"))
	err = root.SetAesGcmKeyBytes(rootKey)
	require.NoError(err)
	r := dbw.New(db)
	w := dbw.New(db)
	kmsCache, err := kms.New(r, w, []kms.KeyPurpose{kms.KeyPurposeRootKey, "oplog"}, kms.WithTableNamePrefix("kms_oplog"))
	require.NoError(err)
	err = kmsCache.AddExternalWrapper(ctx, kms.KeyPurposeRootKey, root)
	require.NoError(err)
	err = kmsCache.CreateKeys(ctx, "global", []kms.KeyPurpose{"oplog"})
	require.NoError(err)
	wrapper, err := kmsCache.GetWrapper(ctx, "global", "oplog")
	require.NoError(err)
	return db, wrapper
}

func testOpen(t testing.TB, dbType string, connectionUrl string) *dbw.DB {
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

func testUser(t testing.TB, db *dbw.DB, name, phoneNumber, email string) *oplog_test.TestUser {
	t.Helper()
	u := &oplog_test.TestUser{
		Name:        name,
		PhoneNumber: phoneNumber,
		Email:       email,
	}
	require.NoError(t, dbw.New(db).Create(context.Background(), u))
	return u
}

func testFindUser(t testing.TB, db *dbw.DB, userId uint32) *oplog_test.TestUser {
	t.Helper()
	var foundUser oplog_test.TestUser
	require.NoError(t, dbw.New(db).LookupWhere(context.Background(), &foundUser, "id = ?", []any{userId}))
	return &foundUser
}

func testId(t testing.TB) string {
	t.Helper()
	id, err := dbw.NewId("i")
	require.NoError(t, err)
	return id
}

func testInitDbInDocker(t testing.TB) (cleanup func() error, retURL string, err error) {
	t.Helper()
	require := require.New(t)
	cleanup, retURL, _, err = dbtest.StartUsingTemplate(dbtest.Postgres)
	require.NoError(err)
	testInitStore(t, cleanup, retURL)
	return cleanup, retURL, err
}

// testInitStore will execute the migrations needed to initialize the store for tests
func testInitStore(t testing.TB, cleanup func() error, url string) {
	t.Helper()
	ctx := context.Background()
	dialect := "postgres"

	d, err := common.SqlOpen(dialect, url)
	require.NoError(t, err)
	sm, err := schema.NewManager(ctx, schema.Dialect(dialect), d)
	require.NoError(t, err)
	t.Cleanup(func() { sm.Close(context.Background()) })
	_, err = sm.ApplyMigrations(ctx)
	require.NoError(t, err)
}

type constraintResults struct {
	Name      string
	TableName string
}

func testListConstraints(t testing.TB, db *dbw.DB, tableName string) []constraintResults {
	t.Helper()
	require := require.New(t)
	require.NotEmpty(tableName)
	testCtx := context.Background()
	const constraintSql = `select pgc.conname as name,
	ccu.table_schema as table_schema,
	ccu.table_name,
	ccu.column_name,
	pg_get_constraintdef(pgc.oid) as definition
from pg_constraint pgc
join pg_namespace nsp on nsp.oid = pgc.connamespace
join pg_class  cls on pgc.conrelid = cls.oid
left join information_schema.constraint_column_usage ccu
	   on pgc.conname = ccu.constraint_name
	   and nsp.nspname = ccu.constraint_schema
-- where contype ='c'
where ccu.table_name = ?
order by ccu.table_name,pgc.conname `

	rw := dbw.New(db)
	rows, err := rw.Query(testCtx, constraintSql, []any{tableName})
	require.NoError(err)
	results := []constraintResults{}
	for rows.Next() {
		var r constraintResults
		rw.ScanRows(rows, &r)
		results = append(results, r)
	}
	require.NoError(err)
	return results
}
