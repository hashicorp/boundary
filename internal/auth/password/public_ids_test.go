// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package password

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_PublicIds(t *testing.T) {
	ctx := context.Background()
	t.Run("authMethod", func(t *testing.T) {
		id, err := newAuthMethodId(ctx)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, globals.PasswordAuthMethodPrefix+"_"))
	})
	t.Run("account", func(t *testing.T) {
		id, err := newAccountId(ctx)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, globals.PasswordAccountPrefix+"_"))
	})
}
