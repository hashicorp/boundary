// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package hostcatalogscmd

import (
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func (c *StaticCommand) extraStaticHelpFunc(helpMap map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary host-catalogs create static [options] [args]",
			"",
			"  Create a static-type host catalog. Example:",
			"",
			`    $ boundary host-catalogs create static -scope-id p_1234567890 -name prodops -description "Static host-catalog for ProdOps"`,
			"",
			"",
		})

	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary host-catalogs update static [options] [args]",
			"",
			"  Update a static-type host catalog given its ID. Example:",
			"",
			`    $ boundary host-catalogs update static -id hcst_1234567890 -name "devops" -description "Static host-catalog for DevOps"`,
			"",
			"",
		})
	}
	return helpStr + c.Flags().Help()
}
