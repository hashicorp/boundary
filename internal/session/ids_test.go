// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

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
	ctx := context.Background()
	t.Run("s", func(t *testing.T) {
		id, err := newId(ctx)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, globals.SessionPrefix+"_"))
	})
	t.Run("ss", func(t *testing.T) {
		id, err := newStateId(ctx)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, StatePrefix+"_"))
	})
	t.Run("sc", func(t *testing.T) {
		id, err := newConnectionId(ctx)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, ConnectionPrefix+"_"))
	})
	t.Run("scs", func(t *testing.T) {
		id, err := newConnectionStateId(ctx)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(id, ConnectionStatePrefix+"_"))
	})
}
