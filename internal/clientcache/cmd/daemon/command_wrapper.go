// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/hashicorp/boundary/internal/clientcache/internal/daemon"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/mitchellh/cli"
)

// Keep this interface aligned with the interface at internal/cmd/commands.go
type cacheEnabledCommand interface {
	cli.Command
	BaseCommand() *base.Command
}

// CommandWrapper starts the boundary daemon after the command was Run and attempts
// to send the current persona to any running daemon.
type CommandWrapper struct {
	cacheEnabledCommand
}

// Wrap returns a cli.CommandFactory that returns a command wrapped in the CommandWrapper.
func Wrap(c cacheEnabledCommand) cli.CommandFactory {
	return func() (cli.Command, error) {
		return &CommandWrapper{
			cacheEnabledCommand: c,
		}, nil
	}
}

// Run runs the wrapped command and then attempts to start the boundary daemon and send
// the current persona
func (w *CommandWrapper) Run(args []string) int {
	if w.BaseCommand().FlagSkipCacheDaemon {
		return w.cacheEnabledCommand.Run(args)
	}

	// potentially intercept the token in case it isn't stored in the keyring
	var token string
	w.cacheEnabledCommand.BaseCommand().Opts = append(w.cacheEnabledCommand.BaseCommand().Opts, base.WithInterceptedToken(&token))
	r := w.cacheEnabledCommand.Run(args)

	if r != base.CommandSuccess {
		// if we were not successful in running our command, do not continue to
		// start the daemon and add the token.
		return r
	}

	ctx := context.Background()
	if w.startDaemon(ctx) {
		w.addTokenToCache(ctx, token)
	}
	return r
}

// startDaemon attempts to start a daemon and returns true if we have attempted to start
// the daemon and either it was successful or it was already running.
func (w *CommandWrapper) startDaemon(ctx context.Context) bool {
	cmdName, err := os.Executable()
	if err != nil {
		w.BaseCommand().UI.Error(fmt.Sprintf("unable to find boundary binary for daemon startup: %s", err.Error()))
		return false
	}

	var stdErr bytes.Buffer
	cmd := exec.Command(cmdName, "daemon", "start", "-background")
	cmd.Stderr = &stdErr

	// We use Run here instead of Start because the command spawns off a subprocess and returns.
	// We do not want to send the request to add a persona to the cache until we know the daemon
	// has started up.
	err = cmd.Run()
	return err == nil || strings.Contains(stdErr.String(), "already running")
}

// addTokenToCache runs AddTokenCommand with the token used in, or retrieved by
// the wrapped command.
func (w *CommandWrapper) addTokenToCache(ctx context.Context, token string) bool {
	com := AddTokenCommand{Command: base.NewCommand(w.BaseCommand().UI)}
	client, err := w.BaseCommand().Client()
	if err != nil {
		return false
	}
	keyringType, tokName, err := w.BaseCommand().DiscoverKeyringTokenInfo()
	if err != nil {
		return false
	}
	if token != "" {
		client.SetToken(token)
	}

	// Since the daemon might have just started, we need to wait until it can
	// respond to our requests
	waitCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := waitForDaemon(waitCtx); err != nil {
		// TODO: Print the result of this out into a log in the dot directory
		return false
	}

	_, apiErr, err := com.Add(ctx, client, keyringType, tokName)
	return err == nil && apiErr == nil
}

// waitForDaemon continually looks for the unix socket until it is found or the
// provided context is done. It returns an error if the unix socket is not found
// before the context is done.
func waitForDaemon(ctx context.Context) error {
	const op = "daemon.waitForDaemon"
	dotPath, err := DefaultDotDirectory(ctx)
	if err != nil {
		return err
	}
	timer := time.NewTimer(0)

	addr, err := daemon.SocketAddress(dotPath)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	_, err = os.Stat(addr.Path)
	for os.IsNotExist(err) {
		select {
		case <-timer.C:
		case <-ctx.Done():
			return ctx.Err()
		}
		_, err = os.Stat(addr.Path)
		timer.Reset(10 * time.Millisecond)
	}
	return nil
}
