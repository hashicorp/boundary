package dbassert

import (
	"testing"

	dbassert "github.com/hashicorp/dbassert"
	gormAssert "github.com/hashicorp/dbassert/gorm"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
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
	assert := assert.New(t)
	gormDb, err := gorm.Open("postgres", conn)
	assert.NoError(err)
	r := db.New(gormDb)
	mockery := new(dbassert.MockTesting)
	dbassert := New(mockery, r)

	dbassert.FieldDomain(&gormAssert.TestModel{}, "PublicId", "dbasserts_public_id")
	mockery.AssertNoError(t)

	mockery.Reset()
	dbassert.FieldDomain(&gormAssert.TestModel{}, "nullable", "dbasserts_public_id")
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
	assert := assert.New(t)
	gormDb, err := gorm.Open("postgres", conn)
	assert.NoError(err)
	r := db.New(gormDb)
	mockery := new(dbassert.MockTesting)
	dbassert := New(mockery, r)

	dbassert.FieldNullable(&gormAssert.TestModel{}, "Nullable")
	mockery.AssertNoError(t)

	mockery.Reset()
	dbassert.FieldNullable(&gormAssert.TestModel{}, "PublicId")
	mockery.AssertError(t)
}

func Test_FieldIsNull(t *testing.T) {
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
	assert := assert.New(t)
	gormDb, err := gorm.Open("postgres", conn)
	assert.NoError(err)
	r := db.New(gormDb)
	mockery := new(dbassert.MockTesting)
	dbassert := New(mockery, r)

	v := 1
	m := gormAssert.CreateTestModel(t, gormDb, nil, &v)

	dbassert.FieldIsNull(&m, "Nullable")
	mockery.AssertNoError(t)

	mockery.Reset()
	dbassert.FieldIsNull(&m, "typeint")
	mockery.AssertError(t)
}

func Test_FieldNotNull(t *testing.T) {
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
	assert := assert.New(t)
	gormDb, err := gorm.Open("postgres", conn)
	assert.NoError(err)
	r := db.New(gormDb)
	mockery := new(dbassert.MockTesting)
	dbassert := New(mockery, r)

	v := 1
	m := gormAssert.CreateTestModel(t, gormDb, nil, &v)

	dbassert.FieldNotNull(&m, "Nullable")
	mockery.AssertError(t)

	mockery.Reset()
	dbassert.FieldNotNull(&m, "typeint")
	mockery.AssertNoError(t)
}
