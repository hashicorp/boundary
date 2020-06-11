package iam

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_PublicIds(t *testing.T) {
	t.Run("role", func(t *testing.T) {
		id, err := newRoleId()
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, RolePrefix+"_"))
	})
}
