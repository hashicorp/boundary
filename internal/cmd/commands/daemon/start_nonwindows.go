// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows
// +build !windows

package daemon

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"syscall"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/mitchellh/go-homedir"
	"github.com/mitchellh/go-ps"
	"github.com/sevlyar/go-daemon"
)

const (
	dotDirectoryNameTemplate = "%s/.boundary"
	pidFileName              = "cache.pid"
	logFileName              = "cache.log"
)

// DefaultDotDirectory returns the default path to the boundary dot directory.
func DefaultDotDirectory(ctx context.Context) (string, error) {
	const op = "daemon.DefaultDotDirectory"
	homeDir, err := homedir.Dir()
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	return fmt.Sprintf(dotDirectoryNameTemplate, homeDir), nil
}

// start will ensure this is the only daemon running and spin off a seperate process.
func (s *StartCommand) start(ctx context.Context, cmd commander, srv server) error {
	const op = "daemon.(StartCommand).start"
	switch {
	case util.IsNil(ctx):
		return errors.New(ctx, errors.InvalidParameter, op, "context is missing")
	}

	dotPath, err := DefaultDotDirectory(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	pid, err := daemon.ReadPidFile(filepath.Join(dotPath, pidFileName))
	if err == nil {
		proc, err := ps.FindProcess(pid)
		switch {
		case err != nil:
			return errors.Wrap(ctx, err, op)
		case proc != nil:
			return errors.New(ctx, errors.Internal, op, fmt.Sprintf("cache daemon (pid %d) is already running.", proc.Pid()))
		}
	}

	var daemonCtx *daemon.Context
	{
		if err := os.MkdirAll(dotPath, os.ModePerm); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		daemonCtx = &daemon.Context{
			PidFileName: filepath.Join(dotPath, pidFileName),
			PidFilePerm: 0o644,
			LogFileName: filepath.Join(dotPath, logFileName),
			LogFilePerm: 0o640,
			WorkDir:     dotPath,
			Umask:       0o27,
		}

		termHandler := func(sig os.Signal) error {
			_ = srv.shutdown()
			return daemon.ErrStop
		}
		daemon.SetSigHandler(termHandler, syscall.SIGQUIT)
		daemon.SetSigHandler(termHandler, syscall.SIGTERM)
	}

	l, err := listener(ctx, dotPath)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	if err := srv.setupLogging(ctx, os.Stderr); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	go func() {
		srv.serve(ctx, cmd, l)
	}()

	{
		// okay, we're ready to make this thing into a daemon
		d, err := daemonCtx.Reborn()
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if d != nil {
			return nil
		}
		defer daemonCtx.Release()

		err = daemon.ServeSignals()
		if err != nil {
			log.Printf("Error: %s", err.Error())
		}

		event.WriteSysEvent(ctx, op, "daemon terminated")
		_ = srv.shutdown()
	}
	return nil
}
