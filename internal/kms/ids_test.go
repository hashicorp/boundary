package kms

import (
	"context"
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
	t.Run("ktk", func(t *testing.T) {
		id, err := newTokenKeyId()
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, TokenKeyPrefix+"_"))
	})
	t.Run("ktkv", func(t *testing.T) {
		id, err := newTokenKeyVersionId()
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, TokenKeyVersionPrefix+"_"))
	})
	t.Run("ksk", func(t *testing.T) {
		id, err := newSessionKeyId()
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, SessionKeyPrefix+"_"))
	})
	t.Run("kskv", func(t *testing.T) {
		id, err := newSessionKeyVersionId()
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, SessionKeyVersionPrefix+"_"))
	})
	t.Run("koidck", func(t *testing.T) {
		id, err := newOidcKeyId()
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, OidcKeyPrefix+"_"))
	})
	t.Run("koidckv", func(t *testing.T) {
		id, err := newOidcKeyVersionId()
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, OidcKeyVersionPrefix+"_"))
	})
	t.Run("kak", func(t *testing.T) {
		id, err := newAuditKeyId(context.Background())
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, AuditKeyPrefix+"_"))
	})
	t.Run("kakv", func(t *testing.T) {
		id, err := newAuditKeyVersionId(context.Background())
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, AuditKeyVersionPrefix+"_"))
	})
}
