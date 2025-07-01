// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package dbw

import (
	"sort"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ColumnValue defines a column and it's assigned value for a database
// operation.  See: SetColumnValues(...)
type ColumnValue struct {
	// Column name
	Column string
	// Value is the column's value
	Value interface{}
}

// Column represents a table Column
type Column struct {
	// Name of the column
	Name string
	// Table name of the column
	Table string
}

func (c *Column) toAssignment(column string) clause.Assignment {
	return clause.Assignment{
		Column: clause.Column{Name: column},
		Value:  clause.Column{Table: c.Table, Name: c.Name},
	}
}

func rawAssignment(column string, value interface{}) clause.Assignment {
	return clause.Assignment{
		Column: clause.Column{Name: column},
		Value:  value,
	}
}

// ExprValue encapsulates an expression value for a column assignment.  See
// Expr(...) to create these values.
type ExprValue struct {
	Sql  string
	Vars []interface{}
}

func (ev *ExprValue) toAssignment(column string) clause.Assignment {
	return clause.Assignment{
		Column: clause.Column{Name: column},
		Value:  gorm.Expr(ev.Sql, ev.Vars...),
	}
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
func Expr(expr string, args ...interface{}) ExprValue {
	return ExprValue{Sql: expr, Vars: args}
}

// SetColumnValues defines a map from column names to values for database
// operations.
func SetColumnValues(columnValues map[string]interface{}) []ColumnValue {
	keys := make([]string, 0, len(columnValues))
	for key := range columnValues {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	assignments := make([]ColumnValue, len(keys))
	for idx, key := range keys {
		assignments[idx] = ColumnValue{Column: key, Value: columnValues[key]}
	}
	return assignments
}

// SetColumns defines a list of column (names) to update using the set of
// proposed insert columns during an on conflict update.
func SetColumns(names []string) []ColumnValue {
	assignments := make([]ColumnValue, len(names))
	for idx, name := range names {
		assignments[idx] = ColumnValue{
			Column: name,
			Value:  Column{Name: name, Table: "excluded"},
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
	Target interface{}

	// Action specifies the action to take on conflict. This can be any one of
	// these:
	//	DoNothing: leaves the conflicting record as-is
	//  UpdateAll: updates all the columns of the conflicting record using the resource's data
	//  []ColumnValue: update a set of columns of the conflicting record using the set of assignments
	Action interface{}
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
