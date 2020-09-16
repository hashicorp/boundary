package hostcatalogs

import (
	"fmt"
	"net/http"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/hostcatalogs"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/common"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/sdk/strutil"
	"github.com/kr/pretty"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var _ cli.Command = (*Command)(nil)
var _ cli.CommandAutocomplete = (*Command)(nil)

type Command struct {
	*base.Command

	Func string
}

func (c *Command) Synopsis() string {
	switch c.Func {
	case "create":
		return "Create host-catalog resources within Boundary"
	case "update":
		return "Update host-catalog resources within Boundary"
	default:
		return common.SynopsisFunc(c.Func, "host-catalog")
	}
}

var flagsMap = map[string][]string{
	"read":   {"id"},
	"delete": {"id"},
	"list":   {"scope-id"},
}

func (c *Command) Help() string {
	helpMap := common.HelpMap("host-catalog")
	var helpStr string
	switch c.Func {
	case "":
		return base.WrapForHelpText([]string{
			"Usage: boundary host-catalogs [sub command] [options] [args]",
			"",
			"  This command allows operations on Boundary host-catalog resources. Example:",
			"",
			"    Read a host-catalog:",
			"",
			`      $ boundary host-catalogs read -id hcst_1234567890`,
			"",
			"  Please see the host-catalogs subcommand help for detailed usage information.",
		})
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary host-catalogs create [type] [sub command] [options] [args]",
			"",
			"  This command allows create operations on Boundary host-catalog resources. Example:",
			"",
			"    Create a static-type host-catalog:",
			"",
			`      $ boundary host-catalogs create static -name prodops -description "For ProdOps usage"`,
			"",
			"  Please see the typed subcommand help for detailed usage information.",
		})
	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary host-catalogs update [type] [sub command] [options] [args]",
			"",
			"  This command allows update operations on Boundary host-catalog resources. Example:",
			"",
			"    Update a static-type host-catalog:",
			"",
			`      $ boundary host-catalogs update static -id hcst_1234567890 -name devops -description "For DevOps usage"`,
			"",
			"  Please see the typed subcommand help for detailed usage information.",
		})
	default:
		helpStr = helpMap[c.Func]()
	}
	return helpStr + c.Flags().Help()
}

func (c *Command) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)

	if len(flagsMap[c.Func]) > 0 {
		f := set.NewFlagSet("Command Options")
		common.PopulateCommonFlags(c.Command, f, resource.HostCatalog.String(), flagsMap[c.Func])
	}

	return set
}

func (c *Command) AutocompleteArgs() complete.Predictor {
	return complete.PredictAnything
}

func (c *Command) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *Command) Run(args []string) int {
	switch c.Func {
	case "", "create", "update":
		return cli.RunResultHelp
	}

	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	if strutil.StrListContains(flagsMap[c.Func], "id") && c.FlagId == "" {
		c.UI.Error("ID is required but not passed in via -id")
		return 1
	}
	if strutil.StrListContains(flagsMap[c.Func], "scope-id") && c.FlagScopeId == "" {
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

	existed := true
	var result api.GenericResult
	var listResult api.GenericListResult
	var apiErr *api.Error

	switch c.Func {
	case "read":
		result, apiErr, err = hostcatalogClient.Read(c.Context, c.FlagId, opts...)
	case "delete":
		_, apiErr, err = hostcatalogClient.Delete(c.Context, c.FlagId, opts...)
		if apiErr != nil && apiErr.Status == int32(http.StatusNotFound) {
			existed = false
			apiErr = nil
		}
	case "list":
		listResult, apiErr, err = hostcatalogClient.List(c.Context, c.FlagScopeId, opts...)
	}

	plural := "host catalog"
	if c.Func == "list" {
		plural = "host catalogs"
	}
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error trying to %s %s: %s", c.Func, plural, err.Error()))
		return 2
	}
	if apiErr != nil {
		c.UI.Error(fmt.Sprintf("Error from controller when performing %s on %s: %s", c.Func, plural, pretty.Sprint(apiErr)))
		return 1
	}

	switch c.Func {
	case "delete":
		switch base.Format(c.UI) {
		case "json":
			c.UI.Output("null")
		case "table":
			output := "The delete operation completed successfully"
			switch existed {
			case true:
				output += "."
			default:
				output += ", however the resource did not exist at the time."
			}
			c.UI.Output(output)
		}
		return 0

	case "list":
		listedCatalogs := listResult.GetItems().([]*hostcatalogs.HostCatalog)
		switch base.Format(c.UI) {
		case "json":
			if len(listedCatalogs) == 0 {
				c.UI.Output("null")
				return 0
			}
			b, err := base.JsonFormatter{}.Format(listedCatalogs)
			if err != nil {
				c.UI.Error(fmt.Errorf("Error formatting as JSON: %w", err).Error())
				return 1
			}
			c.UI.Output(string(b))

		case "table":
			if len(listedCatalogs) == 0 {
				c.UI.Output("No host catalogs found")
				return 0
			}
			var output []string
			output = []string{
				"",
				"Host Catalog information:",
			}
			for i, m := range listedCatalogs {
				if i > 0 {
					output = append(output, "")
				}
				if true {
					output = append(output,
						fmt.Sprintf("  ID:             %s", m.Id),
						fmt.Sprintf("    Version:      %d", m.Version),
						fmt.Sprintf("    Type:         %s", m.Type),
					)
				}
				if m.Name != "" {
					output = append(output,
						fmt.Sprintf("    Name:         %s", m.Name),
					)
				}
				if m.Description != "" {
					output = append(output,
						fmt.Sprintf("    Description:  %s", m.Description),
					)
				}
			}
			c.UI.Output(base.WrapForHelpText(output))
		}
		return 0
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
