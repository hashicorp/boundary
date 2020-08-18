package kms_test

import (
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Ids(t *testing.T) {
	t.Parallel()
	t.Run("krk", func(t *testing.T) {
		id, err := kms.NewRootKeyId()
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, kms.RootKeyPrefix+"_"))
	})
	t.Run("krkv", func(t *testing.T) {
		id, err := kms.NewRootKeyVersionId()
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, kms.RootKeyVersionPrefix+"_"))
	})
}
