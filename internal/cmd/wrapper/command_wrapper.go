// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package wrapper

import (
	"context"
	"errors"
	"sync"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/mitchellh/cli"
)

var ErrCallbackAlreadyRegistered = errors.New("registered callback already exists")

// PostSuccessfulCommandCallback is a function that should be run after the
// wrapped command completes successfully. token will contain the value for any
// new token obtained during the running of the command
type PostSuccessfulCommandCallback func(ctx context.Context, badeCmd *base.Command, token string)

var callbacks sync.Map

// RegisterSuccessfulCommandCallback registers a callback to be run after a
// successful command.
func RegisterSuccessfulCommandCallback(name string, fn PostSuccessfulCommandCallback) error {
	if _, existed := callbacks.Swap(name, fn); existed {
		return ErrCallbackAlreadyRegistered
	}
	return nil
}

type WrappableCommand interface {
	cli.Command
	BaseCommand() *base.Command
}

// CommandWrapper starts the boundary cache after the command was Run and attempts
// to send the current persona to any running daemon.
type CommandWrapper struct {
	WrappableCommand
}

// Wrap returns a cli.CommandFactory that returns a command wrapped in the CommandWrapper.
func Wrap(c func() WrappableCommand) cli.CommandFactory {
	return func() (cli.Command, error) {
		return &CommandWrapper{
			WrappableCommand: c(),
		}, nil
	}
}

// Run runs the wrapped command and then attempts to start the boundary cache and send
// the current token to it.
func (w *CommandWrapper) Run(args []string) int {
	// potentially intercept the token in case it isn't stored in the keyring
	var token string
	w.BaseCommand().Opts = append(w.BaseCommand().Opts, base.WithInterceptedToken(&token))
	r := w.WrappableCommand.Run(args)

	if r != base.CommandSuccess {
		// if we were not successful in running our command, do not continue to
		// start the daemon and add the token.
		return r
	}

	ctx := context.Background()
	callbacks.Range(func(key, value any) bool {
		val := value.(PostSuccessfulCommandCallback)
		val(ctx, w.BaseCommand(), token)
		return true
	})
	return r
}
