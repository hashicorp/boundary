// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPidInUse(t *testing.T) {
	ctx := context.Background()
	dotPath := t.TempDir()
	pidPath := filepath.Join(dotPath, "boundary.pid")

	used, err := pidFileInUse(ctx, pidPath)
	assert.NoError(t, err)
	assert.Nil(t, used)

	workingPidCleanup1, err := writePidFile(ctx, pidPath)
	assert.NoError(t, err)

	used, err = pidFileInUse(ctx, pidPath)
	assert.NoError(t, err)
	assert.NotNil(t, used)

	failingPidCleanup, err := writePidFile(ctx, pidPath)
	assert.Error(t, err)

	used, err = pidFileInUse(ctx, pidPath)
	assert.NoError(t, err)
	assert.NotNil(t, used)

	assert.NoError(t, failingPidCleanup())

	used, err = pidFileInUse(ctx, pidPath)
	assert.NoError(t, err)
	assert.NotNil(t, used)

	assert.NoError(t, workingPidCleanup1())

	used, err = pidFileInUse(ctx, pidPath)
	assert.NoError(t, err)
	assert.Nil(t, used)

	workingPidCleanup2, err := writePidFile(ctx, pidPath)
	assert.NoError(t, err)

	used, err = pidFileInUse(ctx, pidPath)
	assert.NoError(t, err)
	assert.NotNil(t, used)

	assert.NoError(t, workingPidCleanup2())

	used, err = pidFileInUse(ctx, pidPath)
	assert.NoError(t, err)
	assert.Nil(t, used)
}
