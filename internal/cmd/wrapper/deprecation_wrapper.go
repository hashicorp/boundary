// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package wrapper

import (
	"fmt"

	"github.com/mitchellh/cli"
)

// DeprecationWrapper can be used to mark a command as deprecated.
type DeprecationWrapper struct {
	WrappableCommand
	old string
	new string
}

// WrapForDeprecation returns a cli.CommandFactory that will print a deprecation warning when invoked.
func WrapForDeprecation(c func() WrappableCommand, old, new string) cli.CommandFactory {
	return func() (cli.Command, error) {
		return &DeprecationWrapper{
			WrappableCommand: c(),
			old:              old,
			new:              new,
		}, nil
	}
}

// Run prints a deprecation warning and then runs the wrapped command.
func (w *DeprecationWrapper) Run(args []string) int {
	w.WrappableCommand.BaseCommand().UI.Warn(
		fmt.Sprintf(
			"The '%s' command is deprecated and will be removed in a future release. Please use the '%s' command instead.",
			w.old,
			w.new,
		),
	)

	return w.WrappableCommand.Run(args)
}
