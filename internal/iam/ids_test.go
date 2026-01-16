// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_PublicIds(t *testing.T) {
	ctx := context.Background()
	t.Run("role", func(t *testing.T) {
		id, err := newRoleId(ctx)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, globals.RolePrefix+"_"))
	})
	t.Run("user", func(t *testing.T) {
		id, err := newUserId(ctx)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, globals.UserPrefix+"_"))
	})
	t.Run("group", func(t *testing.T) {
		id, err := newGroupId(ctx)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, globals.GroupPrefix+"_"))
	})
	t.Run("oidc managed group", func(t *testing.T) {
		assert.True(t, strings.HasPrefix("mgoidc_1234567890", globals.OidcManagedGroupPrefix+"_"))
	})
	t.Run("scopes", func(t *testing.T) {
		id, err := newScopeId(ctx, scope.Org)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, scope.Org.Prefix()))

		id, err = newScopeId(ctx, scope.Project)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, scope.Project.Prefix()))

		id, err = newScopeId(ctx, scope.Unknown)
		require.Error(t, err)
		assert.Empty(t, id)
		assert.True(t, errors.Match(errors.T(errors.InvalidParameter), err))
	})
}
