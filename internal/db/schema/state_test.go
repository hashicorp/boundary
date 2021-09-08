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
