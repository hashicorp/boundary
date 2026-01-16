// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package schema

import "github.com/hashicorp/boundary/internal/db/schema/internal/provider"

const nilVersion = -1

// State contains information regarding the current state of a boundary database's schema.
type State struct {
	// Initialized indicates if the current database has been previously initialized.
	Initialized bool
	Editions    []EditionState
}

// MigrationsApplied checks to see that all Editions are in the Equal SchemaState.
func (s State) MigrationsApplied() bool {
	for _, e := range s.Editions {
		if e.DatabaseSchemaState != Equal {
			return false
		}
	}
	return true
}

func (s State) databaseState() provider.DatabaseState {
	dbState := make(provider.DatabaseState)
	for _, e := range s.Editions {
		dbState[e.Name] = e.DatabaseSchemaVersion
	}
	return dbState
}

// DatabaseState defines the state of the Database schema as compared to the
// latest version for the binary.
type DatabaseState int

// Valid states.
const (
	Behind DatabaseState = iota // Database schema version is older then latest for the binary, so it needs migrations applied.
	Ahead                       // Database schema version is newer then latest for the binary, so binary needs to be updated.
	Equal                       // Database schema version matches latest version for the binary.
)

// EditionState is the current state of a schema Edition.
type EditionState struct {
	// Name is the identifier of the Edition.
	Name string

	// DatabaseSchemaVersion is the schema version that is currently running in the database.
	DatabaseSchemaVersion int
	// BinarySchemaVersion is the schema version which this boundary binary supports.
	BinarySchemaVersion int

	DatabaseSchemaState DatabaseState
}

func compareVersions(d int, b int) DatabaseState {
	if d == b {
		return Equal
	}

	if d < b {
		return Behind
	}

	return Ahead
}
