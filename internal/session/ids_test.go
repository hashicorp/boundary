package session

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Ids(t *testing.T) {
	t.Parallel()
	t.Run("s", func(t *testing.T) {
		id, err := newId()
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, SessionPrefix+"_"))
	})
	t.Run("ss", func(t *testing.T) {
		id, err := newStateId()
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, StatePrefix+"_"))
	})
	t.Run("sc", func(t *testing.T) {
		id, err := newConnectionId()
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, ConnectionPrefix+"_"))
	})
	t.Run("scs", func(t *testing.T) {
		id, err := newConnectionStateId()
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, ConnectionStatePrefix+"_"))
	})
}
