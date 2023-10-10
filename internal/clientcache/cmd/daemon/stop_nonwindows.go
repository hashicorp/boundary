// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows
// +build !windows

package daemon

import (
	"context"
	"path/filepath"
	"syscall"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/util"
)

// stop will send a term signal to the daemon to shut down.
func (s *StopCommand) stop(ctx context.Context) error {
	const op = "daemon.(StopCommand).stop"
	switch {
	case util.IsNil(ctx):
		return errors.New(ctx, errors.InvalidParameter, op, "context is missing")
	}

	dotPath, err := DefaultDotDirectory(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	pidPath := filepath.Join(dotPath, pidFileName)
	p, err := pidFileInUse(ctx, pidPath)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if p == nil {
		return errors.New(ctx, errors.NotFound, op, "daemon not running")
	}
	if err := p.Signal(syscall.SIGTERM); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("sending sigterm to process"))
	}
	return nil
}
