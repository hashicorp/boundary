// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
	"io"
	"net"
	"strings"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

const DefaultRefreshIntervalSeconds = 5 * 60

var (
	_ cli.Command             = (*StartCommand)(nil)
	_ cli.CommandAutocomplete = (*StartCommand)(nil)
)

type server interface {
	setupLogging(context.Context, io.Writer) error
	serve(context.Context, commander, net.Listener) error
	shutdown() error
}

type StartCommand struct {
	*base.Command

	flagRefreshIntervalSeconds int64
	flagDatabaseUrl            string
	flagLogLevel               string
	flagLogFormat              string
	flagStoreDebug             bool
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
	f.Int64Var(&base.Int64Var{
		Name:    "refresh-interval-seconds",
		Target:  &c.flagRefreshIntervalSeconds,
		Usage:   `If set, specifies the number of seconds between cache refreshes. Default: 5 minutes`,
		Aliases: []string{"r"},
		Default: DefaultRefreshIntervalSeconds,
	})
	f.BoolVar(&base.BoolVar{
		Name:    "store-debug",
		Target:  &c.flagStoreDebug,
		Default: false,
		Usage:   `Turn on store debugging`,
		Aliases: []string{"d"},
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
	c.Context = ctx
	c.ContextCancel = cancel

	var err error
	f := c.Flags()
	if err := f.Parse(args); err != nil {
		c.PrintCliError(err)
		return base.CommandUserError
	}

	cfg := serverConfig{
		contextCancel:          c.ContextCancel,
		refreshIntervalSeconds: c.flagRefreshIntervalSeconds,
		flagDatabaseUrl:        c.flagDatabaseUrl,
		flagStoreDebug:         c.flagStoreDebug,
		flagLogLevel:           c.flagLogLevel,
		flagLogFormat:          c.flagLogFormat,
		ui:                     c.UI,
	}
	srv, err := newServer(c.Context, cfg)
	if err != nil {
		c.UI.Error(err.Error())
		return base.CommandUserError
	}

	if err := c.start(c.Context, c, srv); err != nil {
		c.PrintCliError(err)
		return base.CommandUserError
	}

	return base.CommandSuccess
}

func (c *StartCommand) StartCacheInBackground(ctx context.Context) error {
	const op = "daemon.(StartCommand).StartCacheInBackground"

	cancelCtx, cancelFunc := context.WithCancel(ctx)

	cfg := serverConfig{
		contextCancel:          cancelFunc,
		refreshIntervalSeconds: DefaultRefreshIntervalSeconds,
		ui:                     c.UI,
	}
	srv, err := newServer(ctx, cfg)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if err := c.start(cancelCtx, c, srv); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}
