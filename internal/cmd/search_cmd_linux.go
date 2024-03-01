// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cmd

import (
	"github.com/hashicorp/boundary/internal/clientcache/cmd/daemon"
	"github.com/hashicorp/boundary/internal/clientcache/cmd/search"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/mitchellh/cli"
)

func init() {
	extraCommandsFuncs = append(extraCommandsFuncs, func(ui, serverCmdUi cli.Ui, runOpts *RunOptions) {
		Commands["daemon"] = func() (cli.Command, error) {
			return &daemon.DaemonCommand{
				Command: base.NewCommand(ui),
			}, nil
		}
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
		Commands["daemon status"] = func() (cli.Command, error) {
			return &daemon.StatusCommand{
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
