// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	stderrors "errors"
	"fmt"
	"io"
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
	"github.com/posener/complete"
	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	dotDirname  = ".boundary"
	pidFileName = "cache.pid"
	logFileName = "cache.log"

	// Mark of process as having been started in the background
	backgroundEnvName = "_BOUNDARY_CACHE_BACKGROUND"
	backgroundEnvVal  = "1"
)

var (
	_ cli.Command             = (*StartCommand)(nil)
	_ cli.CommandAutocomplete = (*StartCommand)(nil)
)

type StartCommand struct {
	*base.Command

	flagRefreshInterval         time.Duration
	flagRecheckSupportInterval  time.Duration
	flagMaxSearchStaleness      time.Duration
	flagMaxSearchRefreshTimeout time.Duration
	flagDatabaseUrl             string
	flagLogLevel                string
	flagLogFormat               string
	flagStoreDebug              bool
	flagBackground              bool
	flagForceResetSchema        bool
}

func (c *StartCommand) Synopsis() string {
	return "Start a Boundary cache"
}

func (c *StartCommand) Help() string {
	helpText := `
Usage: boundary cache start [options]

  Start a cache:

      $ boundary cache start

  For a full list of examples, please see the documentation.

` + c.Flags().Help()
	return strings.TrimSpace(helpText)
}

func (c *StartCommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetNone)

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
		Hidden: true,
	})
	f.DurationVar(&base.DurationVar{
		Name:    "refresh-interval",
		Target:  &c.flagRefreshInterval,
		Usage:   `Specifies the interval between refresh token supported cache refreshes.`,
		Default: daemon.DefaultRefreshInterval,
	})
	f.DurationVar(&base.DurationVar{
		Name:    "recheck-support-interval",
		Target:  &c.flagRecheckSupportInterval,
		Usage:   `Specifies the interval between checking if a boundary instances is supported when it previously was not.`,
		Default: daemon.DefaultRecheckSupportInterval,
		Hidden:  true,
	})
	f.DurationVar(&base.DurationVar{
		Name:    "max-search-staleness",
		Target:  &c.flagMaxSearchStaleness,
		Usage:   `Specifies the duration of time that can pass since the resource was last updated before performing a search waits for the resources being refreshed first.`,
		Default: daemon.DefaultSearchStaleness,
	})
	f.DurationVar(&base.DurationVar{
		Name:    "max-search-refresh-timeout",
		Target:  &c.flagMaxSearchRefreshTimeout,
		Usage:   `If a search request triggers a best effort refresh, this specifies how long the refresh should run before timing out.`,
		Default: daemon.DefaultSearchRefreshTimeout,
	})
	f.BoolVar(&base.BoolVar{
		Name:    "store-debug",
		Target:  &c.flagStoreDebug,
		Default: false,
		Usage:   `Turn on sqlite query debugging. This is deprecated. Users should use -log-level=debug instead.`,
		Aliases: []string{"d"},
		Hidden:  true,
	})
	f.BoolVar(&base.BoolVar{
		Name:    "background",
		Target:  &c.flagBackground,
		Default: false,
		Usage:   `Run the cache daemon in the background`,
	})
	f.BoolVar(&base.BoolVar{
		Name:    "force-reset-schema",
		Target:  &c.flagForceResetSchema,
		Default: false,
		Usage:   `Force resetting the cache schema and all contained data`,
		Hidden:  true,
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

	continueRun, writers, cleanup, err := c.makeBackground(ctx, dotDir)
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

	lf, logFileName, err := logFile(ctx, dotDir, 5)
	if err != nil {
		c.PrintCliError(err)
		return base.CommandCliError
	}
	defer lf.Close()
	writers = append(writers, lf)

	if c.flagStoreDebug {
		c.UI.Warn("The -store-debug flag is now ignored. Use -log-level=debug instead for debugging purposes.")
	}

	cfg := &daemon.Config{
		ContextCancel:           cancel,
		RefreshInterval:         c.flagRefreshInterval,
		RecheckSupportInterval:  c.flagRecheckSupportInterval,
		MaxSearchStaleness:      c.flagMaxSearchStaleness,
		MaxSearchRefreshTimeout: c.flagMaxSearchRefreshTimeout,
		DatabaseUrl:             c.flagDatabaseUrl,
		LogLevel:                c.flagLogLevel,
		LogFormat:               c.flagLogFormat,
		LogWriter:               io.MultiWriter(writers...),
		LogFileName:             logFileName,
		DotDirectory:            dotDir,
		RunningInBackground:     os.Getenv(backgroundEnvName) == backgroundEnvVal,
		ForceResetSchema:        c.flagForceResetSchema,
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
	const op = "cache.DefaultDotDirectory"
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	return filepath.Join(homeDir, dotDirname), nil
}

// logFile returns a log file which is rotated after it reaches the provided
// maximum size in mb before being rotated out.  The rotated out log file gets
// a suffix that matches the time that the rotation happened. Up to 3 log files
// are saved as backup. When a new log file is rotated and there is already 3
// backups created, the oldest one is deleted.
func logFile(ctx context.Context, dotDir string, maxSizeMb int) (io.WriteCloser, string, error) {
	const op = "cache.logFile"
	logFilePath := filepath.Join(dotDir, logFileName)
	{
		// Ensure the file is created with the desired permissions.
		logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, "", errors.Wrap(ctx, err, op)
		}
		logFile.Close()
	}

	logFile := &lumberjack.Logger{
		Filename:   logFilePath,
		MaxSize:    maxSizeMb,
		MaxBackups: 3,
		Compress:   true,
	}
	return logFile, logFilePath, nil
}

func (c *StartCommand) makeBackground(ctx context.Context, dotDir string) (bool, []io.Writer, pidCleanup, error) {
	const op = "cache.makeBackground"

	writers := []io.Writer{}
	pidPath := filepath.Join(dotDir, pidFileName)
	if running, err := pidFileInUse(ctx, pidPath); running != nil {
		return false, writers, noopPidCleanup, stderrors.New("The cache is already running.")
	} else if err != nil && !errors.Match(errors.T(errors.NotFound), err) {
		return false, writers, noopPidCleanup, fmt.Errorf("Error when checking if the cache pid is in use: %w.", err)
	}

	if !c.flagBackground && os.Getenv(backgroundEnvName) != backgroundEnvVal {
		writers = append(writers, os.Stderr)
	}

	if !c.flagBackground || os.Getenv(backgroundEnvName) == backgroundEnvVal {
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
	args := []string{"cache", "start"}
	args = append(args, "-refresh-interval", c.flagRefreshInterval.String())
	args = append(args, "-max-search-staleness", c.flagMaxSearchStaleness.String())
	args = append(args, "-max-search-refresh-timeout", c.flagMaxSearchRefreshTimeout.String())
	args = append(args, "-recheck-support-interval", c.flagRecheckSupportInterval.String())
	if c.flagLogLevel != "" {
		args = append(args, "-log-level", c.flagLogLevel)
	}
	if c.flagLogFormat != "" {
		args = append(args, "-log-format", c.flagLogFormat)
	}
	if c.flagDatabaseUrl != "" {
		args = append(args, "-database-url", c.flagDatabaseUrl)
	}
	cmd := exec.Command(absPath, args...)
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
