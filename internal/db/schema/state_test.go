package schema

import (
	"context"
	"database/sql"
	"testing"

	"github.com/hashicorp/boundary/internal/docker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestState(t *testing.T) {
	c, u, _, err := docker.StartDbInDocker("postgres")
	t.Cleanup(func() {
		if err := c(); err != nil {
			t.Fatalf("Got error at cleanup: %v", err)
		}
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, c())
	})
	ctx := context.Background()
	d, err := sql.Open("postgres", u)
	require.NoError(t, err)

	m, err := NewManager(ctx, "postgres", d)
	require.NoError(t, err)
	want := &State{
		BinarySchemaVersion: BinarySchemaVersion("postgres"),
	}
	s, err := m.State(ctx)
	require.NoError(t, err)
	assert.Equal(t, want, s)

	testDriver, err := newPostgres(ctx, d)
	require.NoError(t, err)
	require.NoError(t, testDriver.setVersion(ctx, 2, true))

	want = &State{
		InitializationStarted: true,
		BinarySchemaVersion:   BinarySchemaVersion("postgres"),
		Dirty:                 true,
		CurrentSchemaVersion:  2,
	}
	s, err = m.State(ctx)
	require.NoError(t, err)
	assert.Equal(t, want, s)
}
