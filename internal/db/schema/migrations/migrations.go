package migrations

import (
	"context"
	"database/sql"
)

type MigrationCallback func(context.Context, *sql.Tx) error

type UpVersion struct {
	Statements []byte
	PreHook    MigrationCallback
	PostHook   MigrationCallback
}

// MigrationState is meant to be populated by the generated migration code and
// contains the internal representation of a schema in the current binary.
type MigrationState struct {
	// BinarySchemaVersion provides the database schema version supported by
	// this binary.
	BinarySchemaVersion int

	UpMigrations map[int]UpVersion
}
