// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// Package gorm provides a set of assertions for testing Go database
// applications that use gorm.
//
// Example Usage:
//
//	import (
//		"testing"
//
//		dbassert "github.com/hashicorp/dbassert/gorm"
//	)
//
//	func TestSomeDatabase(t *testing.T) {
//		conn, err := sql.Open("postgres", "postgres://postgres:secret@localhost:db?sslmode=disable")
//		if err != nil {
//			t.Fatal(err)
//		}
//		defer conn.Close()
//		db, err := gorm.Open("postgres", conn)
//		m := testModel{}
//		if err = db.Create(&m).Error; err != nil {
//			t.Fatal(err)
//		}
//		dbassert := dbassert.New(t, conn, "postgres")
//		dbassert.IsNull(&someModel, "someField")
//	}
package gorm
