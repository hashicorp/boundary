// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package dbassert

import (
	"database/sql"
	"errors"
	"reflect"

	"github.com/stretchr/testify/assert"
)

var ErrNilTestingT = errors.New("TestingT is nil")

// DbAsserts provides database assertion methods around the TestingT
// interface.
type DbAsserts struct {
	T       TestingT
	Db      *sql.DB
	Dialect string
}

// New creates a new DbAsserts.
func New(t TestingT, db *sql.DB, dialect string) *DbAsserts {
	if isNil(t) {
		panic(ErrNilTestingT)
	}
	if !assert.NotNil(t, db, "db is nill") {
		return nil
	}
	if !assert.NotEmpty(t, dialect, "dialect is not set") {
		return nil
	}
	switch dialect {
	case "postgres":
	default:
		assert.FailNowf(t, "%s not a supported dialect", dialect)
		return nil
	}
	return &DbAsserts{
		T:       t,
		Db:      db,
		Dialect: dialect,
	}
}

// TestingT is the testing interface used by the dbassert package.
type TestingT interface {
	Errorf(format string, args ...interface{})
	FailNow()
}

// THelper is the helper interface used by the dbassert package.
type THelper interface {
	Helper()
}

func isNil(i interface{}) bool {
	if i == nil {
		return true
	}
	switch reflect.TypeOf(i).Kind() {
	case reflect.Ptr, reflect.Map, reflect.Array, reflect.Chan, reflect.Slice:
		return reflect.ValueOf(i).IsNil()
	}
	return false
}
