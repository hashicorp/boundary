package sessions

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Ids(t *testing.T) {
	t.Parallel()
	t.Run("s", func(t *testing.T) {
		id, err := newSessionId()
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, SessionPrefix+"_"))
	})
	t.Run("ss", func(t *testing.T) {
		id, err := newSessionStateId()
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, SessionStatePrefix+"_"))
	})
}
