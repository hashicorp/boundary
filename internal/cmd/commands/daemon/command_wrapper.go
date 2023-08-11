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

// wrappableCommand defines the interface for the commands that can be wrapped.
type wrappableCommand interface {
	cli.Command
	commander
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

	ctx := context.Background()
	if w.startDaemon(ctx) {
		w.addPersonaInCache(ctx)
	}
	return r
}

// startDaemon attempts to start a daemon and returns true if we have attempted to start
// the daemon and either it was successful or it was already running.
func (w *CommandWrapper) startDaemon(ctx context.Context) bool {
	args := os.Args

	binary, err := exec.LookPath(args[0])
	if binary == "" && err != nil {
		binary, err = exec.LookPath("." + string(os.PathSeparator) + args[0])
		if err != nil {
			w.ui.Error(fmt.Sprintf("unable to find boundary binary for daemon startup: %s", err.Error()))
			return false
		}
	}
	args[0] = binary

	var stdErr bytes.Buffer
	cmd := exec.Command(args[0], "daemon", "start")
	cmd.Stderr = &stdErr
	cmd.Env = os.Environ()
	// We use Run here instead of Start because the command spawns off a subprocess and returns.
	// We do not want to send the request to add a persona to the cache until we know the daemon
	// has starte dup.
	err = cmd.Run()
	return err == nil || strings.Contains(stdErr.String(), "already running")
}

// addPersonaInCache runs AddPersonaCommand
func (w *CommandWrapper) addPersonaInCache(ctx context.Context) bool {
	c := AddPersonaCommand{Command: base.NewCommand(w.ui)}
	c.Flags()
	if err := c.AddPersona(ctx); err != nil {
		return false
	}
	return true
}
