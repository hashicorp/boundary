package iam

import (
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/intglobals"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_PublicIds(t *testing.T) {
	t.Run("role", func(t *testing.T) {
		id, err := newRoleId()
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, RolePrefix+"_"))
	})
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
	t.Run("oidc managed group", func(t *testing.T) {
		assert.True(t, strings.HasPrefix("mgoidc_1234567890", intglobals.OidcManagedGroupPrefix+"_"))
	})
	t.Run("scopes", func(t *testing.T) {
		id, err := newScopeId(scope.Org)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, scope.Org.Prefix()))

		id, err = newScopeId(scope.Project)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, scope.Project.Prefix()))

		id, err = newScopeId(scope.Unknown)
		require.Error(t, err)
		assert.Empty(t, id)
		assert.True(t, errors.Match(errors.T(errors.InvalidParameter), err))
	})
}
