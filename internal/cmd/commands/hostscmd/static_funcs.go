// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package hostscmd

import (
	"github.com/hashicorp/boundary/api/hosts"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func init() {
	extraStaticActionsFlagsMapFunc = extraStaticActionsFlagsMapFuncImpl
	extraStaticFlagsFunc = extraStaticFlagsFuncImpl
	extraStaticFlagsHandlingFunc = extraStaticFlagsHandlingFuncImpl
}

type extraStaticCmdVars struct {
	flagAddress string
}

func extraStaticActionsFlagsMapFuncImpl() map[string][]string {
	return map[string][]string{
		"create": {"address"},
		"update": {"address"},
	}
}

func (c *StaticCommand) extraStaticHelpFunc(helpMap map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary hosts create static [options] [args]",
			"",
			"  Create a static-type host. Example:",
			"",
			`    $ boundary hosts create static -name prodops -description "Static host for ProdOps" -address "127.0.0.1"`,
			"",
			"",
		})

	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary hosts update static [options] [args]",
			"",
			"  Update a static-type host given its ID. Example:",
			"",
			`    $ boundary hosts update static -id hst_1234567890 -name "devops" -description "Static host for DevOps" -address "10.20.30.40"`,
			"",
			"",
		})
	default:
		helpStr = helpMap[c.Func]()
	}

	return helpStr + c.Flags().Help()
}

func extraStaticFlagsFuncImpl(c *StaticCommand, set *base.FlagSets, _ *base.FlagSet) {
	f := set.NewFlagSet("Static Host Options")

	for _, name := range flagsStaticMap[c.Func] {
		switch name {
		case "address":
			f.StringVar(&base.StringVar{
				Name:   "address",
				Target: &c.flagAddress,
				Usage:  "The address of the host",
			})
		}
	}
}

func extraStaticFlagsHandlingFuncImpl(c *StaticCommand, _ *base.FlagSets, opts *[]hosts.Option) bool {
	if c.Func == "create" && c.flagAddress == "" {
		c.UI.Error("Address must be provided via -address")
		return false
	}

	switch c.flagAddress {
	case "":
	case "null":
		*opts = append(*opts, hosts.DefaultStaticHostAddress())
	default:
		*opts = append(*opts, hosts.WithStaticHostAddress(c.flagAddress))
	}

	return true
}
