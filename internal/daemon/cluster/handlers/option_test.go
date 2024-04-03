// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package handlers

import (
	"context"
	"crypto/rand"
	"io"
	"testing"

	"github.com/hashicorp/nodeenrollment/storage/inmem"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()

	t.Run("withKeyProducer", func(t *testing.T) {
		storage, err := inmem.New(context.Background())
		require.NoError(t, err)
		creds, err := types.NewNodeCredentials(context.Background(), storage)
		require.NoError(t, err)
		opts := getOpts(WithKeyProducer(creds))
		testOpts := getDefaultOptions()
		assert.Equal(t, nil, testOpts.withKeyProducer)
		assert.Equal(t, creds, opts.withKeyProducer)
	})
	t.Run("WithRandomReader", func(t *testing.T) {
		opts := getOpts(WithRandomReader(io.LimitReader(nil, 0)))
		testOpts := getDefaultOptions()
		assert.Equal(t, rand.Reader, testOpts.withRandomReader)
		assert.NotEqual(t, rand.Reader, opts.withRandomReader)
	})
}
