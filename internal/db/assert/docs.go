// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

// Package dbassert provides a set of assertions for testing the boundary database
// applications.
//
// Example Usage:
//
//	import (
//	    "testing"
//
//	    "github.com/hashicorp/internal/db/assert"
//	)
//
//	func TestSomeDatabase(t *testing.T) {
//	    conn, err := sql.Open("postgres", "postgres://postgres:secret@localhost:%s?sslmode=disable")
//	    if err != nil {
//	        t.Fatal(err)
//	    }
//	    defer conn.Close()
//	    db, err := gorm.Open("postgres", conn)
//	    if err != nil {
//	        t.Fatal(err)
//	    }
//	    m := TestModel{}
//	    if err = rw.Create(&m); err != nil {
//	        t.Fatal(err)
//	    }
//	    dbassert := dbassert.New(t, db)
//	    dbassert.FieldIsNull(&someModel, "someField")
//	}
package dbassert
