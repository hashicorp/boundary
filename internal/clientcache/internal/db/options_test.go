// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package db

import (
	"testing"

	"github.com/hashicorp/go-dbw"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_GetOpts(t *testing.T) {
	t.Parallel()

	t.Run("default", func(t *testing.T) {
		opts, err := getOpts()
		require.NoError(t, err)
		testOpts := options{
			withDbType: dbw.Sqlite,
		}
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithUrl", func(t *testing.T) {
		url := "something"
		opts, err := getOpts(WithUrl(url))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withUrl = url
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithDebug", func(t *testing.T) {
		opts, err := getOpts(WithDebug(true))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withDebug = true
		assert.Equal(t, opts, testOpts)
	})
	t.Run("withTestValidSchemaVersion", func(t *testing.T) {
		version := "v1"
		opts, err := getOpts(withTestValidSchemaVersion(version))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withSchemaVersion = version
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithForceResetSchema", func(t *testing.T) {
		opts, err := getOpts(WithForceResetSchema(true))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		assert.False(t, testOpts.withForceResetSchema)
		testOpts.withForceResetSchema = true
		assert.Equal(t, opts, testOpts)
	})
}
