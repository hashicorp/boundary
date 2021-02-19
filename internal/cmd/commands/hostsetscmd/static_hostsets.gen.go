package hostsetscmd

import (
	"fmt"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/hostsets"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/common"
	"github.com/hashicorp/boundary/sdk/strutil"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

func init() {
}

var (
	_ cli.Command             = (*StaticCommand)(nil)
	_ cli.CommandAutocomplete = (*StaticCommand)(nil)
)

type StaticCommand struct {
	*base.Command

	Func string

	// Used for delete operations
	existed bool
	// Used in some output
	plural string
}

func (c *StaticCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictAnything
}

func (c *StaticCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *StaticCommand) Synopsis() string {
	if extra := c.extraStaticSynopsisFunc(); extra != "" {
		return extra
	}

	return common.SynopsisFunc(c.Func, "host set")
}

func (c *StaticCommand) Help() string {
	var helpStr string
	helpMap := common.HelpMap("host set")

	switch c.Func {
	default:

		helpStr = c.extraStaticHelpFunc(helpMap)
	}

	// Keep linter from complaining if we don't actually generate code using it
	_ = helpMap
	return helpStr
}

var flagsStaticMap = map[string][]string{

	"create": {"host-catalog-id", "name", "description"},

	"update": {"id", "name", "description", "version"},
}

func (c *StaticCommand) Flags() *base.FlagSets {
	if len(flagsStaticMap[c.Func]) == 0 {
		return c.FlagSet(base.FlagSetNone)
	}

	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)
	f := set.NewFlagSet("Command Options")
	common.PopulateCommonFlags(c.Command, f, "static-type host set", flagsStaticMap[c.Func])

	extraStaticFlagsFunc(c, set, f)

	return set
}

func (c *StaticCommand) Run(args []string) int {
	switch c.Func {
	case "":
		return cli.RunResultHelp
	}

	c.plural = "static-type host set"
	switch c.Func {
	case "list":
		c.plural = "static-type host sets"
	}

	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	if strutil.StrListContains(flagsStaticMap[c.Func], "id") && c.FlagId == "" {
		c.UI.Error("ID is required but not passed in via -id")
		return 1
	}

	var opts []hostsets.Option

	if strutil.StrListContains(flagsStaticMap[c.Func], "host-catalog-id") {
		switch c.Func {
		case "create":
			if c.FlagHostCatalogId == "" {
				c.UI.Error("HostCatalog ID must be passed in via -host-catalog-id or BOUNDARY_HOST_CATALOG_ID")
				return 1
			}
		}
	}

	client, err := c.Client()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error creating API client: %s", err.Error()))
		return 2
	}
	hostsetsClient := hostsets.NewClient(client)

	switch c.FlagName {
	case "":
	case "null":
		opts = append(opts, hostsets.DefaultName())
	default:
		opts = append(opts, hostsets.WithName(c.FlagName))
	}

	switch c.FlagDescription {
	case "":
	case "null":
		opts = append(opts, hostsets.DefaultDescription())
	default:
		opts = append(opts, hostsets.WithDescription(c.FlagDescription))
	}

	var version uint32
	switch c.Func {
	case "update":
		switch c.FlagVersion {
		case 0:
			opts = append(opts, hostsets.WithAutomaticVersioning(true))
		default:
			version = uint32(c.FlagVersion)
		}
	}

	if ret := extraStaticFlagsHandlingFunc(c, &opts); ret != 0 {
		return ret
	}

	c.existed = true
	var result api.GenericResult

	switch c.Func {

	case "create":
		result, err = hostsetsClient.Create(c.Context, c.FlagHostCatalogId, opts...)

	case "update":
		result, err = hostsetsClient.Update(c.Context, c.FlagId, version, opts...)

	}

	if err != nil {
		if apiErr := api.AsServerError(err); apiErr != nil {
			c.UI.Error(fmt.Sprintf("Error from controller when performing %s on %s: %s", c.Func, c.plural, base.PrintApiError(apiErr)))
			return 1
		}
		c.UI.Error(fmt.Sprintf("Error trying to %s %s: %s", c.Func, c.plural, err.Error()))
		return 2
	}

	switch c.Func {
	}

	item := result.GetItem().(*hostsets.HostSet)
	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(printItemTable(item))

	case "json":
		b, err := base.JsonFormatter{}.Format(item)
		if err != nil {
			c.UI.Error(fmt.Errorf("Error formatting as JSON: %w", err).Error())
			return 1
		}
		c.UI.Output(string(b))
	}

	return 0
}

var (
	extraStaticFlagsFunc         = func(*StaticCommand, *base.FlagSets, *base.FlagSet) {}
	extraStaticFlagsHandlingFunc = func(*StaticCommand, *[]hostsets.Option) int { return 0 }
)
