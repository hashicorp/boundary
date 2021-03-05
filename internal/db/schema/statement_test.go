package schema

import (
	"testing"

	"github.com/hashicorp/boundary/internal/db/schema/migrations"
	"github.com/stretchr/testify/assert"
)

func TestStatementProvider(t *testing.T) {
	testDialect := "test"
	migrationStates[testDialect] = migrations.MigrationState{
		BinarySchemaVersion: 5,
		UpMigrations: map[int]migrations.UpVersion{
			1: {Statements: []byte("one")},
			2: {Statements: []byte("two")},
			3: {Statements: []byte("three")},
		},
	}

	st := newStatementProvider(testDialect, 1)
	assert.Equal(t, -1, st.Version())
	assert.Equal(t, []byte(nil), st.ReadUp())

	assert.True(t, st.Next())
	assert.Equal(t, 2, st.Version())
	assert.Equal(t, []byte("two"), st.ReadUp())

	assert.True(t, st.Next())
	assert.Equal(t, 3, st.Version())
	assert.Equal(t, []byte("three"), st.ReadUp())

	assert.False(t, st.Next())
	assert.Equal(t, -1, st.Version())
	assert.Equal(t, []byte(nil), st.ReadUp())

	assert.False(t, st.Next())
	assert.Equal(t, -1, st.Version())
	assert.Equal(t, []byte(nil), st.ReadUp())

	st = newStatementProvider("unknown_dialect", nilVersion)
	assert.False(t, st.Next())
}
