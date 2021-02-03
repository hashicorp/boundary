package hostcatalogscmd

import (
	"fmt"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/hostcatalogs"
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

	return common.SynopsisFunc(c.Func, "host catalog")
}

func (c *StaticCommand) Help() string {
	var helpStr string
	helpMap := common.HelpMap("host catalog")

	switch c.Func {
	default:

		helpStr = c.extraStaticHelpFunc(helpMap)
	}

	// Keep linter from complaining if we don't actually generate code using it
	_ = helpMap
	return helpStr
}

var flagsStaticMap = map[string][]string{

	"create": {"scope-id", "name", "description"},

	"update": {"id", "name", "description", "version"},
}

func (c *StaticCommand) Flags() *base.FlagSets {
	if len(flagsStaticMap[c.Func]) == 0 {
		return c.FlagSet(base.FlagSetNone)
	}

	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)
	f := set.NewFlagSet("Command Options")
	common.PopulateCommonFlags(c.Command, f, "static-type host catalog", flagsStaticMap[c.Func])

	return set
}

func (c *StaticCommand) Run(args []string) int {
	switch c.Func {
	case "":
		return cli.RunResultHelp
	}

	c.plural = "static-type host catalog"
	switch c.Func {
	case "list":
		c.plural = "static-type host catalogs"
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

	var opts []hostcatalogs.Option

	if strutil.StrListContains(flagsStaticMap[c.Func], "scope-id") {
		switch c.Func {
		case "create":
			if c.FlagScopeId == "" {
				c.UI.Error("Scope ID must be passed in via -scope-id or BOUNDARY_SCOPE_ID")
				return 1
			}
		}
	}

	client, err := c.Client()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error creating API client: %s", err.Error()))
		return 2
	}
	hostcatalogsClient := hostcatalogs.NewClient(client)

	switch c.FlagName {
	case "":
	case "null":
		opts = append(opts, hostcatalogs.DefaultName())
	default:
		opts = append(opts, hostcatalogs.WithName(c.FlagName))
	}

	switch c.FlagDescription {
	case "":
	case "null":
		opts = append(opts, hostcatalogs.DefaultDescription())
	default:
		opts = append(opts, hostcatalogs.WithDescription(c.FlagDescription))
	}

	switch c.FlagRecursive {
	case true:
		opts = append(opts, hostcatalogs.WithRecursive(true))
	}

	var version uint32
	switch c.Func {
	case "update":
		switch c.FlagVersion {
		case 0:
			opts = append(opts, hostcatalogs.WithAutomaticVersioning(true))
		default:
			version = uint32(c.FlagVersion)
		}
	}

	c.existed = true
	var result api.GenericResult

	switch c.Func {

	case "create":
		result, err = hostcatalogsClient.Create(c.Context, "static", c.FlagScopeId, opts...)

	case "update":
		result, err = hostcatalogsClient.Update(c.Context, c.FlagId, version, opts...)

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

	item := result.GetItem().(*hostcatalogs.HostCatalog)
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
