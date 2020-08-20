package target

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Ids(t *testing.T) {
	t.Parallel()
	t.Run("tcp", func(t *testing.T) {
		id, err := newTcpTargetId()
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, TcpTargetPrefix+"_"))
	})
}
