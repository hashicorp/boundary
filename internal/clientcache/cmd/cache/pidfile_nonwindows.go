// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows
// +build !windows

package cache

import (
	"context"
	stderrors "errors"
	"os"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/sevlyar/go-daemon"
)

func writePidFile(ctx context.Context, pidFile string) (pidCleanup, error) {
	const op = "cache.writePidFile"

	// Determine if we should clean up the file after we are done or if
	// it should stick around in the case of lock aquision error since this
	// file didn't create it.
	var pidExists bool
	_, err := os.Stat(pidFile)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return noopPidCleanup, errors.Wrap(ctx, err, op)
	}
	if err == nil {
		pidExists = true
	}

	f, err := os.OpenFile(pidFile, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return noopPidCleanup, errors.Wrap(ctx, err, op, errors.WithMsg("opening file"))
	}
	closeAndDeleteFileFn := func() error {
		err := f.Close()
		if !pidExists {
			err = stderrors.Join(err, os.Remove(pidFile))
		}
		return err
	}
	l := daemon.NewLockFile(f)
	if err := l.Lock(); err != nil {
		return closeAndDeleteFileFn, errors.Wrap(ctx, err, op)
	}
	// Now that we have acquired the lock and verified we own the pid file
	// we can remove it always when cleaning up.
	unlockAndCleanFn := func() error {
		return l.Remove()
	}
	if err := l.WritePid(); err != nil {
		return unlockAndCleanFn, errors.Wrap(ctx, err, op)
	}
	return unlockAndCleanFn, nil
}

func pidFileInUse(ctx context.Context, pidFile string) (*os.Process, error) {
	const op = "cache.pidFileInUse"
	if pidFile == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "pid filename is empty")
	}
	proc, err := (&daemon.Context{PidFileName: pidFile}).Search()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return proc, nil
}
