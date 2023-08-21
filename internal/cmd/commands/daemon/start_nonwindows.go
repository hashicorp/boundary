// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows
// +build !windows

package daemon

import (
	"context"
	"os"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/sevlyar/go-daemon"
)

func writePidFile(ctx context.Context, pidFile string) (pidCleanup, error) {
	const op = "daemon.writePidFile"
	file, err := daemon.CreatePidFile(pidFile, 0o600)
	if err != nil {
		return noopPidCleanup, errors.Wrap(ctx, err, op)
	}
	return func() error {
		return file.Remove()
	}, nil
}

func pidFileInUse(ctx context.Context, pidFile string) (bool, error) {
	const op = "daemon.pidFileInUse"
	if pidFile == "" {
		return false, errors.New(ctx, errors.InvalidParameter, op, "pid filename is empty")
	}
	proc, err := (&daemon.Context{PidFileName: pidFile}).Search()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	return proc != nil, nil
}
