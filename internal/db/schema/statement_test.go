package schema

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStatementProvider(t *testing.T) {
	testDialect := "test"
	migrationStates[testDialect] = migrationState{
		binarySchemaVersion: 5,
		upMigrations: map[int][]byte{
			1: []byte("one"),
			2: []byte("two"),
			3: []byte("three"),
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
