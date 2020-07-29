package password

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_PrivateIds(t *testing.T) {
	t.Run("argon2Config", func(t *testing.T) {
		id, err := newArgon2ConfigurationId()
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, argon2ConfigurationPrefix+"_"))
	})
}
