package oidc

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientSecret_String(t *testing.T) {
	t.Parallel()
	t.Run("redacted", func(t *testing.T) {
		assert := assert.New(t)
		const want = redactedClientSecret
		tk := ClientSecret("super secret token")
		assert.Equalf(want, tk.String(), "AccessToken.String() = %v, want %v", tk.String(), want)
	})
}

func TestClientSecret_MarshalJSON(t *testing.T) {
	t.Parallel()
	t.Run("redacted", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		want := fmt.Sprintf(`"%s"`, redactedClientSecret)
		tk := ClientSecret("super secret token")
		got, err := tk.MarshalJSON()
		require.NoError(err)
		assert.Equalf([]byte(want), got, "AccessToken.MarshalJSON() = %s, want %s", got, want)
	})
}
