// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build amd64 || arm64

package cmd

import (
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/commands/ferry"
	"github.com/mitchellh/cli"
)

func init() {
	extraCommandsFuncs = append(extraCommandsFuncs, func(ui, serverCmdUi cli.Ui, runOpts *RunOptions) {
		Commands["ferry"] = func() (cli.Command, error) {
			return &ferry.FerryCommand{
				Command: base.NewCommand(ui),
			}, nil
		}
		Commands["ferry add-token"] = func() (cli.Command, error) {
			return &ferry.AddTokenCommand{
				Command: base.NewCommand(ui),
			}, nil
		}
		Commands["ferry status"] = func() (cli.Command, error) {
			return &ferry.StatusCommand{
				Command: base.NewCommand(ui),
			}, nil
		}
	})
}
