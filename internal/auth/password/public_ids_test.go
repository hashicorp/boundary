package password

import (
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/intglobals"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_PublicIds(t *testing.T) {
	t.Run("authMethod", func(t *testing.T) {
		id, err := newAuthMethodId()
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, AuthMethodPrefix+"_"))
	})
	t.Run("account", func(t *testing.T) {
		id, err := newAccountId()
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, intglobals.NewPasswordAccountPrefix+"_"))
	})
}
