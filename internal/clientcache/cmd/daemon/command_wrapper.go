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

// CommandWrapper starts the boundary daemon after the command was Run and attempts
// to send the current persona to any running daemon.
type CommandWrapper struct {
	cli.Command
	ui cli.Ui
}

// Wrap returns a cli.CommandFactory that returns a command wrapped in the CommandWrapper.
func Wrap(ui cli.Ui, wrapped cli.Command) cli.CommandFactory {
	return func() (cli.Command, error) {
		return &CommandWrapper{
			Command: wrapped,
			ui:      ui,
		}, nil
	}
}

// Run runs the wrapped command and then attempts to start the boundary daemon and send
// the current persona
func (w *CommandWrapper) Run(args []string) int {
	r := w.Command.Run(args)

	ctx := context.Background()
	if w.startDaemon(ctx) {
		w.addPersonaInCache(ctx)
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

// addPersonaInCache runs AddPersonaCommand
func (w *CommandWrapper) addPersonaInCache(ctx context.Context) bool {
	c := AddTokenCommand{Command: base.NewCommand(w.ui)}
	c.Flags()
	apiErr, err := c.Add(ctx)
	return err == nil && apiErr == nil
}
