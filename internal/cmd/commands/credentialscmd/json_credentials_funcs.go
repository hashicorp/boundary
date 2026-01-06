// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package credentialscmd

import (
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func (c *JsonCommand) extraJsonHelpFunc(_ map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary credentials create json -credential-store-id [options] [args]",
			"",
			"  Create a json credential. Example:",
			"",
			`    $ boundary credentials create json -credential-store-id csst_1234567890 -object file:///home/user/secret`,
			"",
			"",
		})

	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary credentials update json [options] [args]",
			"",
			"  Update a json credential given its ID. Example:",
			"",
			`    $ boundary credentials update json -id csst_1234567890 -name devops -description "For DevOps usage"`,
			"",
			"",
		})
	}
	return helpStr + c.Flags().Help()
}
