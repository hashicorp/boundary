package schema

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBinarySchemaVersion(t *testing.T) {
	dialect := "test_binaryschemaversion"
	migrationStates[dialect] = migrationState{binarySchemaVersion: 3}
	assert.Equal(t, 3, BinarySchemaVersion(dialect))
	assert.Equal(t, nilVersion, BinarySchemaVersion("unknown_dialect"))
}

func TestDevMigration(t *testing.T) {
	dialect := "test_devmigrations"
	migrationStates[dialect] = migrationState{devMigration: true}
	assert.True(t, DevMigration(dialect))
	migrationStates[dialect] = migrationState{devMigration: false}
	assert.False(t, DevMigration(dialect))
	assert.False(t, DevMigration("unknown_dialect"))
}
