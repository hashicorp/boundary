package schema

const nilVersion = -1

// migrationState is meant to be populated by the generated migration code and
// contains the internal representation of a schema in the current binary.
type migrationState struct {
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

// BinarySchemaVersion provides the schema version that this binary supports for the provided dialect.
// If the binary doesn't support this dialect -1 is returned.
func BinarySchemaVersion(dialect string) int {
	ms, ok := migrationStates[dialect]
	if !ok {
		return nilVersion
	}
	return ms.binarySchemaVersion
}
