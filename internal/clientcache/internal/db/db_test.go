// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package db

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpen(t *testing.T) {
	ctx := context.Background()
	t.Run("success-file-url-with-reopening", func(t *testing.T) {
		tmpDir := t.TempDir()
		db, err := Open(ctx, WithUrl(tmpDir+"/test.db"+fkPragma))
		require.NoError(t, err)
		require.NotNil(t, db)
		assert.FileExists(t, tmpDir+"/test.db")

		info, err := os.Stat(tmpDir + "/test.db")
		require.NoError(t, err)
		origCreatedAt := info.ModTime()

		// Reopen the db and make sure the file is not recreated
		db, err = Open(ctx, WithUrl(tmpDir+"/test.db"+fkPragma))
		require.NoError(t, err)
		require.NotNil(t, db)
		info, err = os.Stat(tmpDir + "/test.db")
		require.NoError(t, err)
		assert.Equal(t, origCreatedAt, info.ModTime())
	})
	t.Run("success-mem-default-url", func(t *testing.T) {
		db, err := Open(ctx)
		require.NoError(t, err)
		require.NotNil(t, db)
	})
	t.Run("recreate-on-version-mismatch", func(t *testing.T) {
		tmpDir := t.TempDir()
		db, err := Open(ctx, WithUrl(tmpDir+"/test.db"+fkPragma))
		require.NoError(t, err)
		require.NotNil(t, db)
		assert.FileExists(t, tmpDir+"/test.db")
		info, err := os.Stat(tmpDir + "/test.db")
		require.NoError(t, err)
		origCreatedAt := info.ModTime()

		// Reopen the db with a different schema version: forcing the db to be recreated
		db, err = Open(ctx, WithUrl(tmpDir+"/test.db"+fkPragma), withTestValidSchemaVersion("2"))
		require.NoError(t, err)
		require.NotNil(t, db)
		info, err = os.Stat(tmpDir + "/test.db")
		require.NoError(t, err)
		// The file should have been recreated with a new timestamp
		assert.NotEqual(t, origCreatedAt, info.ModTime())
	})
}

const (
	dotDirname = ".boundary"
	dbFileName = "cache.db"
	fkPragma   = "?_pragma=foreign_keys(1)"
)
