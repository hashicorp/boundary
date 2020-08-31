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
		id, err := newRootKeyId()
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, RootKeyPrefix+"_"))
	})
	t.Run("krkv", func(t *testing.T) {
		id, err := newRootKeyVersionId()
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, RootKeyVersionPrefix+"_"))
	})
	t.Run("kdk", func(t *testing.T) {
		id, err := newDatabaseKeyId()
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, DatabaseKeyPrefix+"_"))
	})
	t.Run("kdkv", func(t *testing.T) {
		id, err := newDatabaseKeyVersionId()
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, DatabaseKeyVersionPrefix+"_"))
	})
	t.Run("kopk", func(t *testing.T) {
		id, err := newOplogKeyId()
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, OplogKeyPrefix+"_"))
	})
	t.Run("kopkv", func(t *testing.T) {
		id, err := newOplogKeyVersionId()
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, OplogKeyVersionPrefix+"_"))
	})
}
