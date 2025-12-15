// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package genericcmd

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/mitchellh/cli"
)

var _ cli.Command = (*Command)(nil)

type Command struct {
	*base.Command

	Func string
}

func (c *Command) Synopsis() string {
	return fmt.Sprintf("Run a generic %s command against a resource", c.Func)
}

func (c *Command) Help() string {
	aAn := "a"
	if c.Func == "update" {
		aAn = "an"
	}
	return base.WrapForHelpText([]string{
		fmt.Sprintf("Usage: boundary %s [resource ID] [args]", c.Func),
		"",
		fmt.Sprintf("  This command runs %s %s command against the given resource ID. Arguments are the same as the type-specific command.", aAn, c.Func),
		"",
		fmt.Sprintf("  Note: this command forwards to a type-specific command; help/error/cURL output from that command may show the full command syntax."),
	})
}

func (c *Command) Run(args []string) int {
	if len(args) > 0 {
		return cli.RunResultHelp
	}
	return base.CommandSuccess
}
