// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/boundary/internal/clientcache/internal/daemon"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/mitchellh/cli"
	"github.com/mitchellh/go-homedir"
	"github.com/posener/complete"
	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	dotDirname  = ".boundary"
	pidFileName = "cache.pid"
	logFileName = "cache.log"

	// Mark of process as having been started in the background
	backgroundEnvName = "_BOUNDARY_DAEMON_BACKGROUND"
	backgroundEnvVal  = "1"
)

var (
	_ cli.Command             = (*StartCommand)(nil)
	_ cli.CommandAutocomplete = (*StartCommand)(nil)
)

type server interface {
	setupLogging(context.Context, io.Writer) error
	serve(context.Context, daemon.Commander, net.Listener) error
	shutdown() error
}

type StartCommand struct {
	*base.Command

	flagRefreshInterval   time.Duration
	flagFullFetchInterval time.Duration
	flagDatabaseUrl       string
	flagLogLevel          string
	flagLogFormat         string
	flagStoreDebug        bool
	flagBackground        bool
}

func (c *StartCommand) Synopsis() string {
	return "Start a Boundary daemon"
}

func (c *StartCommand) Help() string {
	helpText := `
Usage: boundary daemon start [options]

  Start a daemon:

      $ boundary daemon start

  For a full list of examples, please see the documentation.

` + c.Flags().Help()
	return strings.TrimSpace(helpText)
}

func (c *StartCommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient)

	f := set.NewFlagSet("Command Options")
	f.StringVar(&base.StringVar{
		Name:       "log-level",
		Target:     &c.flagLogLevel,
		EnvVar:     "BOUNDARY_LOG_LEVEL",
		Completion: complete.PredictSet("trace", "debug", "info", "warn", "err"),
		Usage: "Log verbosity level, mostly as a fallback for events. Supported values (in order of more detail to less) are " +
			"\"trace\", \"debug\", \"info\", \"warn\", and \"err\".",
	})
	f.StringVar(&base.StringVar{
		Name:       "log-format",
		Target:     &c.flagLogFormat,
		Completion: complete.PredictSet("standard", "json"),
		Usage:      `Log format, mostly as a fallback for events. Supported values are "standard" and "json".`,
	})
	f.StringVar(&base.StringVar{
		Name:   "database-url",
		Target: &c.flagDatabaseUrl,
		Usage:  `If set, specifies the URL used to connect to the sqlite database (store) for caching. This can refer to a file on disk (file://) from which a URL will be read; an env var (env://) from which the URL will be read; or a direct database URL.`,
	})
	f.DurationVar(&base.DurationVar{
		Name:    "refresh-interval-seconds",
		Target:  &c.flagRefreshInterval,
		Usage:   `If set, specifies the number of seconds between refresh token supported cache refreshes. Default: 1 minute`,
		Default: daemon.DefaultRefreshIntervalSeconds * time.Second,
	})
	f.DurationVar(&base.DurationVar{
		Name:    "full-fetch-interval-seconds",
		Target:  &c.flagFullFetchInterval,
		Usage:   `If set, specifies the number of seconds between full cache refresh for boundary instances which do not support refresh tokens. Default: 5 minutes`,
		Default: daemon.DefaultFullFetchIntervalSeconds * time.Second,
	})
	f.BoolVar(&base.BoolVar{
		Name:    "store-debug",
		Target:  &c.flagStoreDebug,
		Default: false,
		Usage:   `Turn on store debugging`,
		Aliases: []string{"d"},
	})
	f.BoolVar(&base.BoolVar{
		Name:    "background",
		Target:  &c.flagBackground,
		Default: false,
		Usage:   `Turn on store debugging`,
	})

	return set
}

func (c *StartCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictNothing
}

func (c *StartCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *StartCommand) Run(args []string) int {
	const op = "daemon.(StartCommand).Run"
	ctx, cancel := context.WithCancel(c.Context)
	defer cancel()

	var err error
	f := c.Flags()
	if err := f.Parse(args); err != nil {
		c.PrintCliError(err)
		return base.CommandUserError
	}

	dotDir, err := DefaultDotDirectory(ctx)
	if err != nil {
		return base.CommandCliError
	}
	if err := os.MkdirAll(dotDir, 0o700); err != nil {
		c.PrintCliError(err)
		return base.CommandCliError
	}

	continueRun, writers, cleanup, err := makeBackground(ctx, dotDir, c.flagBackground)
	defer func() {
		if cleanup != nil {
			cleanup()
		}
	}()
	if err != nil {
		c.PrintCliError(err)
		return base.CommandCliError
	}
	if !continueRun {
		return base.CommandSuccess
	}

	// TODO: print something out for the spawner to consume in case they can easily
	// report if the daemon started or not.

	logFilePath := filepath.Join(dotDir, logFileName)

	{
		// Ensure the file is created with the desired permissions.
		logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			c.PrintCliError(err)
			return base.CommandCliError
		}
		logFile.Close()
	}

	logFile := &lumberjack.Logger{
		Filename:   logFilePath,
		MaxSize:    5, // megabytes
		MaxBackups: 3,
		Compress:   true,
	}
	defer logFile.Close()
	writers = append(writers, logFile)

	cfg := &daemon.Config{
		ContextCancel:     cancel,
		RefreshInterval:   c.flagRefreshInterval,
		FullFetchInterval: c.flagFullFetchInterval,
		DatabaseUrl:       c.flagDatabaseUrl,
		StoreDebug:        c.flagStoreDebug,
		LogLevel:          c.flagLogLevel,
		LogFormat:         c.flagLogFormat,
		LogWriter:         io.MultiWriter(writers...),
		DotDirectory:      dotDir,
	}

	srv, err := daemon.New(ctx, cfg)
	if err != nil {
		c.UI.Error(err.Error())
		return base.CommandUserError
	}

	var srvErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		srvErr = srv.Serve(ctx, c)
	}()

	// This is a blocking call. We rely on the c.ShutdownCh to cancel this
	// context when sigterm or sigint is received.
	<-ctx.Done()
	if err := srv.Shutdown(ctx); err != nil {
		c.PrintCliError(err)
		return base.CommandCliError
	}
	wg.Wait()
	if srvErr != nil {
		c.PrintCliError(srvErr)
		return base.CommandCliError
	}

	return base.CommandSuccess
}

// DefaultDotDirectory returns the default path to the boundary dot directory.
func DefaultDotDirectory(ctx context.Context) (string, error) {
	const op = "daemon.DefaultDotDirectory"
	homeDir, err := homedir.Dir()
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	return filepath.Join(homeDir, dotDirname), nil
}

func makeBackground(ctx context.Context, dotDir string, runBackgroundFlag bool) (bool, []io.Writer, pidCleanup, error) {
	const op = "daemon.makeBackground"

	writers := []io.Writer{}
	pidPath := filepath.Join(dotDir, pidFileName)
	if running, err := pidFileInUse(ctx, pidPath); running != nil {
		return false, writers, noopPidCleanup, errors.New(ctx, errors.Conflict, op, "daemon already running")
	} else if err != nil && !errors.Match(errors.T(errors.NotFound), err) {
		return false, writers, noopPidCleanup, errors.Wrap(ctx, err, op)
	}

	if !runBackgroundFlag && os.Getenv(backgroundEnvName) != backgroundEnvVal {
		writers = append(writers, os.Stderr)
	}

	if !runBackgroundFlag || os.Getenv(backgroundEnvName) == backgroundEnvVal {
		// We are either already running in the background or background was
		// not requested. Write the pid file and continue.
		cleanup, err := writePidFile(ctx, pidPath)
		if err != nil {
			return false, writers, noopPidCleanup, errors.Wrap(ctx, err, op)
		}
		return true, writers, cleanup, nil
	}

	absPath, err := os.Executable()
	if err != nil {
		return false, writers, noopPidCleanup, errors.Wrap(ctx, err, op)
	}

	env := os.Environ()
	env = append(env, fmt.Sprintf("%s=%s", backgroundEnvName, backgroundEnvVal))
	cmd := exec.Command(absPath, "daemon", "start")
	cmd.Env = env
	if err = cmd.Start(); err != nil {
		return false, writers, noopPidCleanup, errors.Wrap(ctx, err, op)
	}

	// TODO: Read the output from the child process for a brief time
	// to see if we can identify any errors that might arise.
	return false, writers, noopPidCleanup, nil
}

type pidCleanup func() error

var noopPidCleanup pidCleanup = func() error { return nil }
