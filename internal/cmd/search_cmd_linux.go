// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cmd

import (
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/commands/daemon"
	"github.com/hashicorp/boundary/internal/cmd/commands/search"
	"github.com/mitchellh/cli"
)

func init() {
	commandFactoryWrapper = daemonWrap

	extraCommandsFuncs = append(extraCommandsFuncs, func(ui, serverCmdUi cli.Ui, runOpts *RunOptions) {
		Commands["daemon start"] = func() (cli.Command, error) {
			return &daemon.StartCommand{
				Command: base.NewCommand(ui),
			}, nil
		}
		Commands["daemon stop"] = func() (cli.Command, error) {
			return &daemon.StopCommand{
				Command: base.NewCommand(ui),
			}, nil
		}
		Commands["daemon add-token"] = func() (cli.Command, error) {
			return &daemon.AddTokenCommand{
				Command: base.NewCommand(ui),
			}, nil
		}
		Commands["search"] = func() (cli.Command, error) {
			return &search.SearchCommand{
				Command: base.NewCommand(ui),
			}, nil
		}
	})
}

// daemonWrap wrapps the provided wrappableCommand with a daemon writer which
// conditionally starts the client side daemon after the command completes
func daemonWrap(ui cli.Ui, c wrappableCommand) cli.CommandFactory {
	return daemon.Wrap(ui, c)
}
