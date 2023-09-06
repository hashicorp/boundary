// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_SaveError(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx)
	require.NoError(t, err)

	r, err := NewRepository(ctx, s, testAuthTokenLookup)
	require.NoError(t, err)

	testResource := "test_resource_type"
	testErr := fmt.Errorf("test error for %q", testResource)

	t.Run("empty resource type", func(t *testing.T) {
		assert.ErrorContains(t, r.SaveError(ctx, "", testErr), "resource type is empty")
	})
	t.Run("nil error", func(t *testing.T) {
		assert.ErrorContains(t, r.SaveError(ctx, testResource, nil), "error is nil")
	})
	t.Run("success", func(t *testing.T) {
		assert.NoError(t, r.SaveError(ctx, testResource, testErr))
	})

	assert.NoError(t, r.SaveError(ctx, testResource, testErr))
}
