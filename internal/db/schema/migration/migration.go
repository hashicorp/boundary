// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package migration

import (
	"context"
	"database/sql"
)

// Problems are reports of data issues that were identified by a CheckFunc.
type Problems []string

// Repairs are reports of changes made to data by a RepairFunc.
type Repairs []string

// CheckFunc is a function that checks the state of data in the database to
// determine if a migration will fail, and if so to report the data that is
// problematic so it can be fixed.
type CheckFunc func(context.Context, *sql.Tx) (Problems, error)

// RepairFunc is a function that alters data in the database to resolve issues
// that would prevent a migration from successfully running.
type RepairFunc func(context.Context, *sql.Tx) (Repairs, error)

// Hook provides a set of functions that allow for executing checks prior to
// executing migration statements.
type Hook struct {
	CheckFunc  CheckFunc
	RepairFunc RepairFunc

	// RepairDescription will describe what change running the repair function
	// would perform.
	RepairDescription string
}

// Migration is a set of statements that will alter the database structure or
// or data.
type Migration struct {
	Statements []byte
	Edition    string
	Version    int
	PreHook    *Hook
}

// Migrations are a set of migrations by version.
type Migrations map[int]Migration
