// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build windows
// +build windows

package daemon

import (
	"context"
	"os"
	"path/filepath"

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
		if os.IsNotExist(err) {
			return errors.Wrap(ctx, err, op, errors.WithCode(errors.NotFound))
		}
		return errors.Wrap(ctx, err, op, errors.WithMsg("Unable to stop the daemon"))
	}
	if p == nil {
		return errors.New(ctx, errors.NotFound, op, "daemon process was not found")
	}

	if err := p.Kill(); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("killing the daemon"))
	}
	return nil
}
