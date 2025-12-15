// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows
// +build !windows

package cache

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"syscall"

	"github.com/hashicorp/boundary/internal/util"
)

// stop will send a term signal to the cache to shut down.
func (c *StopCommand) stop(ctx context.Context) error {
	switch {
	case util.IsNil(ctx):
		return errors.New("Invalid parameter provided to stop: context is missing")
	}

	dotPath, err := DefaultDotDirectory(ctx)
	if err != nil {
		return fmt.Errorf("Error when getting default dot directory: %w", err)
	}
	pidPath := filepath.Join(dotPath, pidFileName)
	p, err := pidFileInUse(ctx, pidPath)
	if err != nil {
		return fmt.Errorf("Error when checking if the cache's pid file is in use: %w", err)
	}
	if p == nil {
		return errors.New("The cache is not running.")
	}
	if err := p.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("Error when sending sigterm to cache process: %w", err)
	}
	return nil
}
