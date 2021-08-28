package schema

import (
	"github.com/hashicorp/boundary/internal/db/schema/migrations"
	"github.com/hashicorp/boundary/internal/db/schema/postgres"
)

const nilVersion = -1

// migrationStates is populated by the generated migration code with the key being the dialect.
var migrationStates = make(map[string]migrations.MigrationState)

func init() {
	migrationStates["postgres"] = postgres.MigrationStates()
}

// migrationStates is populated by the generated migration code with the key being the dialect.
var migrationStates = make(map[string]migrationState)

func getUpMigration(dialect string, opt ...Option) map[int]migrations.UpVersion {
	opts := getOpts(opt...)
	var ms migrationState
	var ok bool
	if opts.withMigrationStates != nil {
		ms, ok = opts.withMigrationStates[dialect]
	} else {
		ms, ok = migrationStates[dialect]
	}
	if !ok {
		return nil
	}
	return ms.UpMigrations
}

// BinarySchemaVersion provides the schema version that this binary supports for the provided dialect.
// If the binary doesn't support this dialect -1 is returned.
func BinarySchemaVersion(dialect string) int {
	ms, ok := migrationStates[dialect]
	if !ok {
		return nilVersion
	}
	return ms.BinarySchemaVersion
}

func cloneMigrationStates(states map[string]migrationState) map[string]migrationState {
	nStates := map[string]migrationState{}
	for k, s := range states {
		newState := migrationState{
			binarySchemaVersion: s.binarySchemaVersion,
			upMigrations:        map[int][]byte{},
		}
		for v, up := range s.upMigrations {
			cp := make([]byte, len(up))
			copy(cp, up)
			newState.upMigrations[v] = cp
		}
		nStates[k] = newState
	}
	return nStates
}
