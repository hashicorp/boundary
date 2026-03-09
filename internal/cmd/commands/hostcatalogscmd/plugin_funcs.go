// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package hostcatalogscmd

import (
	"fmt"

	"github.com/hashicorp/boundary/api/hostcatalogs"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/go-bexpr"
)

func init() {
	extraPluginFlagsFunc = extraPluginFlagsFuncImpl
	extraPluginActionsFlagsMapFunc = extraPluginActionsFlagsMapFuncImpl
	extraPluginFlagsHandlingFunc = extraPluginFlagHandlingFuncImpl
}

const (
	workerFilterFlagName = "worker-filter"
)

type extraPluginCmdVars struct {
	flagWorkerFilter string
}

func extraPluginActionsFlagsMapFuncImpl() map[string][]string {
	flags := map[string][]string{
		"create": {
			workerFilterFlagName,
		},
	}
	flags["update"] = flags["create"]
	return flags
}

func extraPluginFlagsFuncImpl(c *PluginCommand, set *base.FlagSets, _ *base.FlagSet) {
	f := set.NewFlagSet("Plugin Host Catalog Options")

	for _, name := range flagsPluginMap[c.Func] {
		switch name {
		case workerFilterFlagName:
			f.StringVar(&base.StringVar{
				Name:   workerFilterFlagName,
				Target: &c.flagWorkerFilter,
				Usage:  `A boolean expression to filter which workers can handle dynamic host catalog commands for this host catalog.`,
			})
		}
	}
}

func extraPluginFlagHandlingFuncImpl(c *PluginCommand, f *base.FlagSets, opts *[]hostcatalogs.Option) bool {
	switch c.flagWorkerFilter {
	case "":
	case "null":
		*opts = append(*opts, hostcatalogs.DefaultWorkerFilter())
	default:
		if _, err := bexpr.CreateEvaluator(c.flagWorkerFilter); err != nil {
			c.UI.Error(fmt.Sprintf("Unable to successfully parse filter expression: %s", err))
			return false
		}
		*opts = append(*opts, hostcatalogs.WithWorkerFilter(c.flagWorkerFilter))
	}

	return true
}

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
