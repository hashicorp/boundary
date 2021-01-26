package schema

const nilVersion = -1

// migrationState is meant to be populated by the generated migration code and
// contains the internal representation of a schema in the current binary.
type migrationState struct {
	// devMigration is true if the database schema that would be applied by
	// MigrateStore would be from files in the /dev directory which indicates it would
	// not be safe to run in a non dev environment.
	devMigration bool

	// binarySchemaVersion provides the database schema version supported by
	// this binary.
	binarySchemaVersion int

	upMigrations map[int][]byte
}

// migrationStates is populated by the generated migration code with the key being the dialect.
var migrationStates = make(map[string]migrationState)

func getUpMigration(dialect string) map[int][]byte {
	ms, ok := migrationStates[dialect]
	if !ok {
		return nil
	}
	return ms.upMigrations
}

// DevMigration returns true iff the provided dialect has changes which are still in development.
func DevMigration(dialect string) bool {
	ms, ok := migrationStates[dialect]
	return ok && ms.devMigration
}

// BinarySchemaVersion provides the schema version that this binary supports for the provided dialect.
// If the binary doesn't support this dialect -1 is returned.
func BinarySchemaVersion(dialect string) int {
	ms, ok := migrationStates[dialect]
	if !ok {
		return nilVersion
	}
	return ms.binarySchemaVersion
}
