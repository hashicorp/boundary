// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package hostcatalogscmd

import (
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func (c *PluginCommand) extraPluginHelpFunc(helpMap map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary host-catalogs create plugin [options] [args]",
			"",
			"  Create a plugin-type host catalog. Example:",
			"",
			`    $ boundary host-catalogs create plugin -scope-id p_1234567890 -name prodops -description "Plugin host-catalog for ProdOps"`,
			"",
			"",
		})

	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary host-catalogs update plugin [options] [args]",
			"",
			"  Update a plugin-type host catalog given its ID. Example:",
			"",
			`    $ boundary host-catalogs update plugin -id hc_1234567890 -name "devops" -description "Plugin host-catalog for DevOps"`,
			"",
			"",
		})
	}
	return helpStr + c.Flags().Help()
}
