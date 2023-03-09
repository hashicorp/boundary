// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package password

import (
	"strings"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_PublicIds(t *testing.T) {
	t.Run("authMethod", func(t *testing.T) {
		id, err := newAuthMethodId()
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, globals.PasswordAuthMethodPrefix+"_"))
	})
	t.Run("account", func(t *testing.T) {
		id, err := newAccountId()
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, globals.NewPasswordAccountPrefix+"_"))
	})
}
