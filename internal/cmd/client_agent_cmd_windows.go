// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

//go:build amd64 || arm64

package cmd

import (
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/commands/clientagentcmd"
	"github.com/mitchellh/cli"
)

func init() {
	extraCommandsFuncs = append(extraCommandsFuncs, func(ui, serverCmdUi cli.Ui, runOpts *RunOptions) {
		Commands["client-agent"] = func() (cli.Command, error) {
			return &clientagentcmd.ClientAgentCommand{
				Command: base.NewCommand(ui),
			}, nil
		}
		Commands["client-agent status"] = func() (cli.Command, error) {
			return &clientagentcmd.StatusCommand{
				Command: base.NewCommand(ui),
			}, nil
		}
		Commands["client-agent pause"] = func() (cli.Command, error) {
			return &clientagentcmd.PauseCommand{
				Command: base.NewCommand(ui),
			}, nil
		}
		Commands["client-agent resume"] = func() (cli.Command, error) {
			return &clientagentcmd.ResumeCommand{
				Command: base.NewCommand(ui),
			}, nil
		}
		Commands["client-agent sessions"] = func() (cli.Command, error) {
			return &clientagentcmd.SessionsCommand{
				Command: base.NewCommand(ui),
			}, nil
		}
	})
}
