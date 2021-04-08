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

func getUpMigration(dialect string) map[int]migrations.UpVersion {
	ms, ok := migrationStates[dialect]
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
