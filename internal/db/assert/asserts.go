package dbassert

import (
	dbassert "github.com/hashicorp/dbassert"

	gormAssert "github.com/hashicorp/dbassert/gorm"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
)

// // DbAsserts provides database assertion methods
type DbAsserts struct {
	asserts *gormAssert.GormAsserts
}

// New creates a new DbAsserts
func New(t dbassert.TestingT, r db.Reader) *DbAsserts {
	assert.NotNil(t, r, "db.Reader is nill")

	db, err := r.DB()
	assert.NoError(t, err)
	return &DbAsserts{
		asserts: gormAssert.New(t, db, "postgres"),
	}
}

// IsNull asserts that the resource fieldName is null in the db.
func (a *DbAsserts) IsNull(resource interface{}, fieldName string) bool {
	return a.asserts.FieldIsNull(resource, fieldName)
}

// NotNull asserts that the resource fieldName is not null in the db.
func (a *DbAsserts) NotNull(resource interface{}, fieldName string) bool {
	return a.asserts.FieldNotNull(resource, fieldName)
}

// Nullable asserts that the resource fieldName is nullable in the db.
func (a *DbAsserts) Nullable(resource interface{}, fieldName string) bool {
	return a.asserts.FieldNullable(resource, fieldName)
}

// Domain asserts that the resource fieldName is the domainName in the db.
func (a *DbAsserts) Domain(resource interface{}, fieldName, domainName string) bool {
	return a.asserts.FieldDomain(resource, fieldName, domainName)
}
