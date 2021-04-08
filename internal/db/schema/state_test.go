package schema

import (
	"testing"

	"github.com/hashicorp/boundary/internal/db/schema/migrations"
	"github.com/stretchr/testify/assert"
)

func TestBinarySchemaVersion(t *testing.T) {
	dialect := "test_binaryschemaversion"
	migrationStates[dialect] = migrations.MigrationState{BinarySchemaVersion: 3}
	assert.Equal(t, 3, BinarySchemaVersion(dialect))
	assert.Equal(t, nilVersion, BinarySchemaVersion("unknown_dialect"))
}
