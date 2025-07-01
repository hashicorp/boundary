// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package gorm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	dbassert "github.com/hashicorp/dbassert"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
)

// IsNull asserts that the modelFieldName is null in the db.
func (a *GormAsserts) IsNull(model interface{}, modelFieldName string) bool {
	if h, ok := a.dbassert.T.(dbassert.THelper); ok {
		h.Helper()
	}
	scope := a.gormDb.NewScope(model)
	if zeroFields, ok := checkPrimaryKeys(scope); !ok {
		assert.FailNow(a.dbassert.T, "is null: primary keys have zero value: %v", zeroFields)
		return false
	}
	colName, err := findColumnName(a.gormDb, model, modelFieldName)
	if err != nil {
		assert.FailNow(a.dbassert.T, err.Error())
		return false
	}
	where := fmt.Sprintf("%s is null", colName)
	var cnt int
	if err := a.gormDb.Where(where).Find(model).Count(&cnt).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			assert.NoError(a.dbassert.T, errors.New("field is not null"))
			return false
		}
		assert.NoError(a.dbassert.T, err)
		return false
	}
	if cnt < 1 {
		return false
	}
	return true
}

// NotNull asserts that the modelFieldName is not null in the db.
func (a *GormAsserts) NotNull(model interface{}, modelFieldName string) bool {
	if h, ok := a.dbassert.T.(dbassert.THelper); ok {
		h.Helper()
	}
	scope := a.gormDb.NewScope(model)
	if zeroFields, ok := checkPrimaryKeys(scope); !ok {
		assert.FailNow(a.dbassert.T, "is null: primary keys have zero value: %v", zeroFields)
		return false
	}
	colName, err := findColumnName(a.gormDb, model, modelFieldName)
	if err != nil {
		assert.FailNow(a.dbassert.T, err.Error())
		return false
	}
	where := fmt.Sprintf("%s is not null", colName)
	if err := a.gormDb.Where(where).First(model).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			assert.NoError(a.dbassert.T, errors.New("field is null"))
		}
		assert.NoError(a.dbassert.T, err)
		return false
	}
	return true
}

// Nullable asserts that the modelFieldName nullable in the database.
func (a *GormAsserts) Nullable(model interface{}, modelFieldName string) bool {
	if h, ok := a.dbassert.T.(dbassert.THelper); ok {
		h.Helper()
	}
	colName, err := findColumnName(a.gormDb, model, modelFieldName)
	if err != nil {
		assert.FailNow(a.dbassert.T, err.Error())
		return false
	}
	return a.dbassert.Nullable(tableName(a.gormDb, model), colName)
}

// Domain asserts that the modelFieldName is the domainName in the
// database.
func (a *GormAsserts) Domain(model interface{}, modelFieldName, domainName string) bool {
	if h, ok := a.dbassert.T.(dbassert.THelper); ok {
		h.Helper()
	}
	colName, err := findColumnName(a.gormDb, model, modelFieldName)
	if err != nil {
		assert.FailNow(a.dbassert.T, err.Error())
		return false
	}
	return a.dbassert.Domain(tableName(a.gormDb, model), colName, domainName)
}

func tableName(db *gorm.DB, model interface{}) string {
	return db.NewScope(model).TableName()
}

// findColumnName will find the model's db column name using the fieldName
// parameter.
func findColumnName(db *gorm.DB, model interface{}, fieldName string) (string, error) {
	for _, f := range db.NewScope(model).GetStructFields() {
		if strings.EqualFold(fieldName, f.Name) {
			return f.DBName, nil
		}
	}
	return "", errors.New("modelFieldName not found in model")
}

func checkPrimaryKeys(scope *gorm.Scope) ([]string, bool) {
	ok := true
	var zeroPkFields []string
	for _, field := range scope.PrimaryFields() {
		v := field.Field.Interface()
		if v == reflect.Zero(reflect.TypeOf(v)).Interface() {
			ok = false
			zeroPkFields = append(zeroPkFields, field.Name)
		}
	}
	return zeroPkFields, ok
}
