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

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/mitchellh/cli"
)

// Keep this interface aligned with the interface at internal/cmd/commands.go
type wrappableCommand interface {
	cli.Command
	BaseCommand() *base.Command
}

// CommandWrapper starts the boundary daemon after the command was Run and attempts
// to send the current persona to any running daemon.
type CommandWrapper struct {
	wrappableCommand
	ui cli.Ui
}

// Wrap returns a cli.CommandFactory that returns a command wrapped in the CommandWrapper.
func Wrap(ui cli.Ui, wrapped wrappableCommand) cli.CommandFactory {
	return func() (cli.Command, error) {
		return &CommandWrapper{
			wrappableCommand: wrapped,
			ui:               ui,
		}, nil
	}
}

// Run runs the wrapped command and then attempts to start the boundary daemon and send
// the current persona
func (w *CommandWrapper) Run(args []string) int {
	r := w.wrappableCommand.Run(args)

	if w.BaseCommand().FlagSkipDaemon {
		return r
	}

	ctx := context.Background()
	if w.startDaemon(ctx) {
		w.addTokenToCache(ctx)
	}
	return r
}

// startDaemon attempts to start a daemon and returns true if we have attempted to start
// the daemon and either it was successful or it was already running.
func (w *CommandWrapper) startDaemon(ctx context.Context) bool {
	cmdName, err := os.Executable()
	if err != nil {
		w.ui.Error(fmt.Sprintf("unable to find boundary binary for daemon startup: %s", err.Error()))
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
func (w *CommandWrapper) addTokenToCache(ctx context.Context) bool {
	com := AddTokenCommand{Command: base.NewCommand(w.ui)}
	client, err := w.BaseCommand().Client()
	if err != nil {
		return false
	}
	keyringType, tokName, err := w.BaseCommand().DiscoverKeyringTokenInfo()
	if err != nil {
		return false
	}
	apiErr, err := com.Add(ctx, client, keyringType, tokName)
	return err == nil && apiErr == nil
}
