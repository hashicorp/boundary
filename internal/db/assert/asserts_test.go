// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package dbassert

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	dbassert "github.com/hashicorp/dbassert"
	gormAssert "github.com/hashicorp/dbassert/gorm"
	"github.com/hashicorp/go-secure-stdlib/base62"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_FieldDomain(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := dbassert.TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	}()
	mockery := new(dbassert.MockTesting)
	dbassert := New(mockery, conn)

	dbassert.Domain(&gormAssert.TestModel{}, "PublicId", "dbasserts_public_id")
	mockery.AssertNoError(t)

	mockery.Reset()
	dbassert.Domain(&gormAssert.TestModel{}, "nullable", "dbasserts_public_id")
	mockery.AssertError(t)
}

func Test_FieldNullable(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := dbassert.TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	}()
	mockery := new(dbassert.MockTesting)
	dbassert := New(mockery, conn)

	dbassert.Nullable(&gormAssert.TestModel{}, "Nullable")
	mockery.AssertNoError(t)

	mockery.Reset()
	dbassert.Nullable(&gormAssert.TestModel{}, "PublicId")
	mockery.AssertError(t)
}

func Test_FieldIsNull(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	assert := assert.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	initStore(t, conn)
	require := require.New(t)
	underlyingDB, err := conn.SqlDB(ctx)
	require.NoError(err)
	assert.NoError(err)
	mockery := new(dbassert.MockTesting)
	dbassert := New(mockery, underlyingDB)

	v := 1
	m := createTestModel(t, conn, nil, &v)

	dbassert.IsNull(&m, "Nullable")
	mockery.AssertNoError(t)

	mockery.Reset()
	dbassert.IsNull(&m, "typeint")
	mockery.AssertError(t)
}

func Test_FieldNotNull(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	initStore(t, conn)
	require := require.New(t)
	underlyingDB, err := conn.SqlDB(ctx)
	require.NoError(err)
	mockery := new(dbassert.MockTesting)
	dbassert := New(mockery, underlyingDB)

	v := 1
	m := createTestModel(t, conn, nil, &v)

	dbassert.NotNull(&m, "Nullable")
	mockery.AssertError(t)

	mockery.Reset()
	dbassert.NotNull(&m, "typeint")
	mockery.AssertNoError(t)
}

type testModel struct {
	Id       int `gorm:"primary_key"`
	PublicId string
	Nullable *string
	TypeInt  *int
}

// TableName is required by Gorm to define the model's table name when it
// doesn't match the model's Go type name.
func (*testModel) TableName() string { return "test_table_dbasserts" }

// CreateTestModel is a helper that creates a testModel in the DB.
func createTestModel(t dbassert.TestingT, d *db.DB, nullable *string, typeInt *int) *testModel {
	publicId, err := base62.Random(12)
	assert.NoError(t, err)
	m := testModel{
		PublicId: publicId,
		Nullable: nullable,
		TypeInt:  typeInt,
	}
	rw := db.New(d)
	require.NoError(t, rw.Create(context.Background(), &m))
	return &m
}

func initStore(t *testing.T, d *db.DB) {
	t.Helper()
	const (
		createDomainType = `
create domain dbasserts_public_id as text
check(
  length(trim(value)) > 10
);
comment on domain dbasserts_public_id is
  'dbasserts test domain type';
`
		createTable = `
create table if not exists test_table_dbasserts (
  id bigint generated always as identity primary key,
  public_id dbasserts_public_id not null,
  nullable text,
  type_int int
);
comment on table test_table_dbasserts is
  'dbasserts test table'
`
	)
	rw := db.New(d)

	ctx := context.Background()
	_, err := rw.Exec(ctx, createDomainType, nil)
	require.NoError(t, err)
	_, err = rw.Exec(ctx, createTable, nil)
	require.NoError(t, err)
}
