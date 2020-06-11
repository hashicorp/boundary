package iam

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_PublicIds(t *testing.T) {
	t.Run("user", func(t *testing.T) {
		id, err := newUserId()
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, UserPrefix+"_"))
	})
	t.Run("group", func(t *testing.T) {
		id, err := newGroupId()
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, GroupPrefix+"_"))
	})
}
