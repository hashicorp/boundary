// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// Package mql provides a language that end users can use to query your
// database models, without them having to learn SQL or exposing your
// application to SQL injection.
//
// # Examples
//
// Gorm: https://github.com/go-gorm/gorm
//
//	w, err := mql.Parse(`name="alice" or name="bob"`,User{})
//	if err != nil {
//	  return nil, err
//	}
//	err = db.Where(w.Condition, w.Args...).Find(&users).Error
//
// database/sql: https://pkg.go.dev/database/sql
//
//	w, err := mql.Parse(`name="alice" or name="bob"`,User{})
//	if err != nil {
//	  return nil, err
//	}
//	q := fmt.Sprintf("select * from users where %s", w.Condition)
//	rows, err := db.Query(q, w.Args...)
//
// go-dbw: https://github.com/hashicorp/go-dbw
//
//	w, err := mql.Parse(`name="alice" or name="bob")`,User{})
//	if err != nil {
//	  return nil, err
//	}
//	err := rw.SearchWhere(ctx, &users, w.Condition, w.Args)
//
// # Simple Usage
//
// You define a model you wish to query as a Go struct and provide a mql query. The
// package then uses the query along with a model to generate a parameterized SQL
// where clause.
//
// Fields in your model can be compared with the following operators:
// =, !=, >=, <=, <, >, %
//
// Strings must be quoted. Double quotes ", single quotes ' or backticks ` can
// be used as delimiters. Users can choose whichever supported delimiter makes
// it easier to quote their string.
//
// Comparison operators can have optional leading/trailing whitespace.
//
// The % operator allows you to do partial string matching using LIKE and this
// matching is case insensitive.
//
// The = equality operator is case insensitive when used with string fields.
//
// Comparisons can be combined using: and, or.
//
// More complex queries can be created using parentheses.
//
// See [GRAMMAR.md]: https://github.com/hashicorp/mql/blob/main/GRAMMAR.md for a more complete documentation of mql's grammar.
//
// Example query:
//
//	name="alice" and age > 11 and (region % "Boston" or region="south shore")
package mql
