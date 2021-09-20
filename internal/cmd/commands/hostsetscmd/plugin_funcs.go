package hostsetscmd

import (
	"fmt"

	"github.com/hashicorp/boundary/api/hostsets"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/libs/endpoint"
)

func init() {
	extraPluginActionsFlagsMapFunc = extraPluginActionsFlagsMapFuncImpl
	extraPluginFlagsFunc = extraPluginFlagsFuncImpl
	extraPluginFlagsHandlingFunc = extraPluginFlagsHandlingFuncImpl
}

type extraPluginCmdVars struct {
	flagPreferredEndpoints []string
}

func extraPluginActionsFlagsMapFuncImpl() map[string][]string {
	return map[string][]string{
		"create": {"preferred-endpoint"},
		"update": {"preferred-endpoint"},
	}
}

func (c *PluginCommand) extraPluginHelpFunc(helpMap map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary host-sets create plugin [options] [args]",
			"",
			"  Create a host set of a type provided by a plugin. Example:",
			"",
			`    $ boundary host-sets create plugin -plugin-id plg_1234567890 -name prodops -description "Plugin host-set for ProdOps"`,
			"",
			"",
		})

	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary host-sets update plugin [options] [args]",
			"",
			"  Update a host set of a type provided by a plugin given its ID. Example:",
			"",
			`    $ boundary host-sets update plugin -id hsplg_1234567890 -name "devops" -description "Plugin host-set for DevOps"`,
			"",
			"",
		})
	default:
		helpStr = helpMap[c.Func]()
	}
	return helpStr + c.Flags().Help()
}

func extraPluginFlagsFuncImpl(c *PluginCommand, set *base.FlagSets, f *base.FlagSet) {
	fs := set.NewFlagSet("Plugin Host-Set Options")

	for _, name := range flagsPluginMap[c.Func] {
		switch name {
		case "preferred-endpoint":
			fs.StringSliceVar(&base.StringSliceVar{
				Name:   "preferred-endpoint",
				Target: &c.flagPreferredEndpoints,
				Usage: `An endpoint preference, specified by "cidr:<valid IPv4/6 CIDR>" ` +
					`or "dns:<globbed name>", specifying which IP address or DNS name out ` +
					`of a host's available possibilities should be preferred. May be specified ` +
					`multiple times, which will build up an in-order set of preferences. ` +
					`If no preferences are specified, a value will be chosen _at random_ from ` +
					`all available values. May not be valid for all plugin types.`,
			})
		}
	}
}

func extraPluginFlagsHandlingFuncImpl(c *PluginCommand, _ *base.FlagSets, opts *[]hostsets.Option) bool {
	switch len(c.flagPreferredEndpoints) {
	case 0:
	case 1:
		if c.flagPreferredEndpoints[0] == "null" {
			*opts = append(*opts, hostsets.DefaultPreferredEndpoints())
			break
		}
		fallthrough

	default:
		if _, err := endpoint.NewPreferencer(c.Context, endpoint.WithPreferenceOrder(c.flagPreferredEndpoints)); err != nil {
			c.UI.Error(fmt.Sprintf("Unable to successfully validate preferred endpoints: %s", err))
			return false
		}
		*opts = append(*opts, hostsets.WithPreferredEndpoints(c.flagPreferredEndpoints))
	}

	return true
}
