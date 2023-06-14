// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cache

import (
	"context"
	"strings"
	"time"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

const defaultRefreshInterval = 15 * time.Minute

var (
	_ cli.Command             = (*ServerCommand)(nil)
	_ cli.CommandAutocomplete = (*ServerCommand)(nil)
)

var extraSelfTerminationConditionFuncs []func(*ServerCommand, chan struct{})

type ServerCommand struct {
	*base.Command
	srv *server

	flagPort                   uint
	flagRefreshIntervalSeconds int64
	flagDatabaseUrl            string
	flagLogLevel               string
	flagLogFormat              string
	flagStoreDebug             bool
	flagSignal                 string
}

func (c *ServerCommand) Synopsis() string {
	return "Start a Boundary cache server"
}

func (c *ServerCommand) Help() string {
	helpText := `
Usage: boundary cache server [options]

  Start a cache server:

      $ boundary cache server

  For a full list of examples, please see the documentation.

` + c.Flags().Help()
	return strings.TrimSpace(helpText)
}

func (c *ServerCommand) Flags() *base.FlagSets {
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
	f.Int64Var(&base.Int64Var{
		Name:    "refresh-interval-seconds",
		Target:  &c.flagRefreshIntervalSeconds,
		Usage:   `If set, specifies the number of seconds between cache refreshes`,
		Aliases: []string{"r"},
	})
	f.UintVar(&base.UintVar{
		Name:       "port",
		Target:     &c.flagPort,
		Completion: complete.PredictSet("port"),
		Default:    9203,
		Usage:      `Listener port. Default: 9203`,
		Aliases:    []string{"p"},
	})
	f.BoolVar(&base.BoolVar{
		Name:    "store-debug",
		Target:  &c.flagStoreDebug,
		Default: false,
		Usage:   `Turn on store debugging`,
		Aliases: []string{"d"},
	})
	f.StringVar(&base.StringVar{
		Name:       "signal",
		Target:     &c.flagSignal,
		Completion: complete.PredictSet("quit", "stop"),
		Usage:      `Send signal to the daemon: quit (graceful shutdown) or stop (fast shutdown)`,
		Aliases:    []string{"s"},
	})

	return set
}

func (c *ServerCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictNothing
}

func (c *ServerCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *ServerCommand) Run(args []string) int {
	const op = "cache.(ServerCommand).Run"
	ctx, cancel := context.WithCancel(c.Context)
	c.Context = ctx
	c.ContextCancel = cancel

	var err error
	f := c.Flags()
	if err := f.Parse(args); err != nil {
		c.PrintCliError(err)
		return base.CommandUserError
	}
	_, tokenName, err := c.DiscoverKeyringTokenInfo()
	if err != nil {
		c.UI.Error(err.Error())
		return base.CommandUserError
	}
	cfg := serverConfig{
		contextCancel:          c.ContextCancel,
		refreshIntervalSeconds: c.flagRefreshIntervalSeconds,
		cmd:                    c,
		tokenName:              tokenName,
		flagDatabaseUrl:        c.flagDatabaseUrl,
		flagStoreDebug:         c.flagStoreDebug,
		flagLogLevel:           c.flagLogLevel,
		flagLogFormat:          c.flagLogFormat,
		ui:                     c.UI,
		flagSignal:             c.flagSignal,
	}
	if c.srv, err = newServer(c.Context, cfg); err != nil {
		c.UI.Error(err.Error())
		return base.CommandUserError
	}

	if err := c.srv.start(c.Context, c.flagPort); err != nil {
		c.PrintCliError(err)
		return base.CommandUserError
	}

	return base.CommandSuccess
}

const DefaultRefreshIntervalSeconds = 5 * 60

func StartCacheInBackground(ctx context.Context, tokenName string, cmd commander, ui cli.Ui, flagPort uint) error {
	const op = "cache.StartCacheInBackground"

	cancelCtx, cancelFunc := context.WithCancel(ctx)

	cfg := serverConfig{
		contextCancel:          cancelFunc,
		refreshIntervalSeconds: DefaultRefreshIntervalSeconds,
		cmd:                    cmd,
		tokenName:              tokenName,
		ui:                     ui,
	}
	srv, err := newServer(ctx, cfg)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if err := srv.start(cancelCtx, flagPort); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}
