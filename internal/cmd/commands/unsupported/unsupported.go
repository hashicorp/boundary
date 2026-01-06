// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package unsupported

import (
	"errors"
	"fmt"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/mitchellh/cli"
)

var _ cli.Command = (*UnsupportedCommand)(nil)

// UnsupportedCommand is a command that simply prints out a message indicating
// the requested command is not supported on this platform.
type UnsupportedCommand struct {
	*base.Command
	CommandName string
}

func (c *UnsupportedCommand) notice() string {
	return fmt.Sprintf("'boundary %s' is not supported on this platform.", c.CommandName)
}

func (c *UnsupportedCommand) Synopsis() string {
	return c.notice()
}

func (c *UnsupportedCommand) Help() string {
	return c.notice()
}

func (c *UnsupportedCommand) Run(args []string) int {
	c.Command.PrintCliError(errors.New(c.notice()))
	return base.CommandUserError
}
