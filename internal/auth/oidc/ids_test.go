// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package oidc

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Ids(t *testing.T) {
	t.Parallel()
	ctx := context.TODO()
	t.Run(globals.OidcAuthMethodPrefix, func(t *testing.T) {
		id, err := newAuthMethodId(ctx)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, globals.OidcAuthMethodPrefix+"_"))
	})
	t.Run(globals.OidcAccountPrefix, func(t *testing.T) {
		id, err := newAccountId(ctx, "public-id", "test-issuer", "test-subject")
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, globals.OidcAccountPrefix+"_"))
	})
}
