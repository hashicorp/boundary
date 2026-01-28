// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package credentialstorescmd

import (
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func (c *StaticCommand) extraStaticHelpFunc(helpMap map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary credential-stores create static [options] [args]",
			"",
			"  Create a static-type credential store. Example:",
			"",
			`    $ boundary credential-stores create static -scope-id p_1234567890`,
			"",
			"",
		})

	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary credential-stores update static [options] [args]",
			"",
			"  Update a static-type credential store given its ID. Example:",
			"",
			`    $ boundary credential-stores update static -name devops -description "For DevOps usage"`,
			"",
			"",
		})
	}
	return helpStr + c.Flags().Help()
}
