// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package db

import (
	"sort"
)

// ColumnValue defines a column and it's assigned value for a database operation
type ColumnValue struct {
	column string
	value  any
}

// column represents a table column
type column struct {
	name  string
	table string
}

// ExprValue encapsulates an expression value for a column assignment.  See
// Expr(...) to create these values.
type ExprValue struct {
	sql  string
	vars []any
}

// Expr creates an expression value (ExprValue) which can be used when setting
// column values for database operations. See: Expr(...)
//
// Set name column to null example:
//
//	SetColumnValues(map[string]interface{}{"name": Expr("NULL")})
//
// Set exp_time column to N seconds from now:
//
//	SetColumnValues(map[string]interface{}{"exp_time": Expr("wt_add_seconds_to_now(?)", 10)})
func Expr(expr string, args ...any) ExprValue {
	return ExprValue{sql: expr, vars: args}
}

// SetColumnValues defines a map from column names to values
func SetColumnValues(columnValues map[string]any) []ColumnValue {
	keys := make([]string, 0, len(columnValues))
	for key := range columnValues {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	assignments := make([]ColumnValue, len(keys))
	for idx, key := range keys {
		assignments[idx] = ColumnValue{column: key, value: columnValues[key]}
	}
	return assignments
}

// SetColumns defines a list of column (names) to update using the set of
// proposed insert columns during an on conflict update.
func SetColumns(names []string) []ColumnValue {
	assignments := make([]ColumnValue, len(names))
	for idx, name := range names {
		assignments[idx] = ColumnValue{
			column: name,
			value:  column{name: name, table: "excluded"},
		}
	}
	return assignments
}

// OnConflict specifies how to handle alternative actions to take when an insert
// results in a unique constraint or exclusion constraint error.
type OnConflict struct {
	// Target specifies what conflict you want to define a policy for.  This can
	// be any one of these:
	//	Columns: the name of a specific column or columns
	//  Constraint: the name of a unique constraint
	Target any

	// Action specifies the action to take on conflict. This can be any one of
	// these:
	//	DoNothing: leaves the conflicting record as-is
	//  UpdateAll: updates all the columns of the conflicting record using the resource's data
	//  []ColumnValue: update a set of columns of the conflicting record using the set of assignments
	Action any
}

// Constraint defines database constraint name
type Constraint string

// Columns defines a set of column names
type Columns []string

// DoNothing defines an "on conflict" action of doing nothing
type DoNothing bool

// UpdateAll defines an "on conflict" action of updating all columns using the
// proposed insert column values
type UpdateAll bool
