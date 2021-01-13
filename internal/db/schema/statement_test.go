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
		downMigrations: map[int][]byte{
			1: []byte("down one"),
			2: []byte("down two"),
			3: []byte("down three"),
		},
	}

	st, err := newStatementProvider(testDialect, 1)
	assert.NoError(t, err)
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

	st, err = newStatementProvider("unknown_dialect", nilVersion)
	assert.NoError(t, err)
	assert.False(t, st.Next())
}

func TestStatementProvider_error(t *testing.T) {
	cases := []struct {
		name string
		in   migrationState
	}{
		{
			name: "mismatchLength",
			in: migrationState{
				binarySchemaVersion: 5,
				upMigrations: map[int][]byte{
					1: []byte("one"),
				},
				downMigrations: map[int][]byte{},
			},
		},
		{
			name: "mismatchVersions",
			in: migrationState{
				binarySchemaVersion: 5,
				upMigrations: map[int][]byte{
					1: []byte("one"),
				},
				downMigrations: map[int][]byte{
					2: []byte("two"),
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			migrationStates[tc.name] = tc.in
			defer delete(migrationStates, tc.name)
			_, err := newStatementProvider(tc.name, -1)
			assert.Error(t, err)
		})
	}

}
