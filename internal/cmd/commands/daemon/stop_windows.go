// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build windows
// +build windows

package daemon

import (
	"context"
	"os"
	"path/filepath"
	"syscall"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/sevlyar/go-daemon"
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

	// TODO: use a library that does not say it doesn't support windows,
	//	even if the functions used here are not OS dependent.
	d, err := (&daemon.Context{
		PidFileName: filepath.Join(dotPath, pidFileName),
	}).Search()
	if err != nil {
		if os.IsNotExist(err) {
			return errors.Wrap(ctx, err, op, errors.WithCode(errors.NotFound))
		}
		return errors.Wrap(ctx, err, op, errors.WithMsg("Unable to stop the daemon"))
	}
	if d == nil {
		return errors.New(ctx, errors.NotFound, op, "daemon process was not found")
	}
	d.Signal(syscall.SIGTERM)
	return nil
}
