package kms

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Ids(t *testing.T) {
	t.Parallel()
	t.Run("krk", func(t *testing.T) {
		id, err := NewRootKeyId()
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, RootKeyPrefix+"_"))
	})
	t.Run("krkv", func(t *testing.T) {
		id, err := NewRootKeyVersionId()
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, RootKeyVersionPrefix+"_"))
	})
}
