package hostcatalogs

import (
	"fmt"
	"net/textproto"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/hostcatalogs"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/common"
	"github.com/hashicorp/boundary/sdk/strutil"
	"github.com/kr/pretty"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var _ cli.Command = (*StaticCommand)(nil)
var _ cli.CommandAutocomplete = (*StaticCommand)(nil)

type StaticCommand struct {
	*base.Command

	Func string
}

func (c *StaticCommand) Synopsis() string {
	return fmt.Sprintf("%s a static-type host-catalog within Boundary", textproto.CanonicalMIMEHeaderKey(c.Func))
}

var staticFlagsMap = map[string][]string{
	"create": {"scope-id", "name", "description"},
	"update": {"id", "name", "description", "version"},
}

func (c *StaticCommand) Help() string {
	var info string
	switch c.Func {
	case "create":
		info = base.WrapForHelpText([]string{
			"Usage: boundary host-catalogs static create [options] [args]",
			"",
			"  Create a static-type host-catalog. Example:",
			"",
			`    $ boundary host-catalogs static create -name prodops -description "Static host-catalog for ProdOps"`,
			"",
			"",
		})

	case "update":
		info = base.WrapForHelpText([]string{
			"Usage: boundary host-catalogs static update [options] [args]",
			"",
			"  Update a static-type host-catalog given its ID. Example:",
			"",
			`    $ boundary host-catalogs static update -id hcst_1234567890 -name "devops" -description "Static host-catalog for DevOps"`,
			"",
			"",
		})
	}
	return info + c.Flags().Help()
}

func (c *StaticCommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)

	if len(staticFlagsMap[c.Func]) > 0 {
		f := set.NewFlagSet("Command Options")
		common.PopulateCommonFlags(c.Command, f, "static-type host-catalog", staticFlagsMap[c.Func])
	}

	return set
}

func (c *StaticCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictAnything
}

func (c *StaticCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *StaticCommand) Run(args []string) int {
	if c.Func == "" {
		return cli.RunResultHelp
	}

	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	if strutil.StrListContains(staticFlagsMap[c.Func], "id") && c.FlagId == "" {
		c.UI.Error("ID is required but not passed in via -id")
		return 1
	}
	if strutil.StrListContains(staticFlagsMap[c.Func], "scope-id") && c.FlagScopeId == "" {
		c.UI.Error("Scope ID must be passed in via -scope-id")
		return 1
	}

	client, err := c.Client()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error creating API client: %s", err.Error()))
		return 2
	}

	var opts []hostcatalogs.Option

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

	hostcatalogClient := hostcatalogs.NewClient(client)

	// Perform check-and-set when needed
	var version uint32
	switch c.Func {
	case "create":
		// These don't update so don't need the existing version
	default:
		switch c.FlagVersion {
		case 0:
			opts = append(opts, hostcatalogs.WithAutomaticVersioning(true))
		default:
			version = uint32(c.FlagVersion)
		}
	}

	var result api.GenericResult
	var apiErr *api.Error

	switch c.Func {
	case "create":
		result, apiErr, err = hostcatalogClient.Create(c.Context, "static", c.FlagScopeId, opts...)
	case "update":
		result, apiErr, err = hostcatalogClient.Update(c.Context, c.FlagId, version, opts...)
	}

	plural := "static-type host-catalog"
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error trying to %s %s: %s", c.Func, plural, err.Error()))
		return 2
	}
	if apiErr != nil {
		c.UI.Error(fmt.Sprintf("Error from controller when performing %s on %s: %s", c.Func, plural, pretty.Sprint(apiErr)))
		return 1
	}

	catalog := result.GetItem().(*hostcatalogs.HostCatalog)
	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(generateHostCatalogTableOutput(catalog))
	case "json":
		b, err := base.JsonFormatter{}.Format(catalog)
		if err != nil {
			c.UI.Error(fmt.Errorf("Error formatting as JSON: %w", err).Error())
			return 1
		}
		c.UI.Output(string(b))
	}

	return 0
}
