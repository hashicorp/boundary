// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build linux || darwin
// +build linux darwin

package daemon

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TODO: Write a test for this that can run on windows.
func TestListenerSocketPermissions(t *testing.T) {
	ctx := context.Background()
	l, err := listen(ctx)
	require.NoError(t, err)
	socketFile := l.Addr().String()
	fi, err := os.Stat(socketFile)
	require.NoError(t, err)
	assert.Equal(t, fi.Mode().Type(), os.ModeSocket)
	assert.Equal(t, fs.FileMode(0o600), fi.Mode().Perm(), "permissions were ", fi.Mode().Perm().String())

	socketDirName := filepath.Dir(socketFile)
	di, err := os.Stat(socketDirName)
	require.NoError(t, err)
	assert.Equal(t, di.Mode().Type(), os.ModeDir)
	assert.Equal(t, fs.FileMode(0o700), di.Mode().Perm(), "permissions were ", fi.Mode().Perm().String())
}
