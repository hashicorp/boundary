package hostsets

import (
	"fmt"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/hostsets"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/common"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/vault/sdk/helper/strutil"
	"github.com/kr/pretty"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var _ cli.Command = (*Command)(nil)
var _ cli.CommandAutocomplete = (*Command)(nil)

type Command struct {
	*base.Command

	Func string

	flagHostCatalogId string
}

func (c *Command) Synopsis() string {
	switch c.Func {
	case "create":
		return "Create host-set resources within Boundary"
	case "update":
		return "Update host-set resources within Boundary"
	default:
		return common.SynopsisFunc(c.Func, "host-set")
	}
}

var flagsMap = map[string][]string{
	"read":   {"id"},
	"delete": {"id"},
}

func (c *Command) Help() string {
	helpMap := common.HelpMap("host-set")
	switch c.Func {
	case "":
		return base.WrapForHelpText([]string{
			"Usage: boundary host-sets [sub command] [options] [args]",
			"",
			"  This command allows operations on Boundary host-set resources. Example:",
			"",
			"    Read a host-set:",
			"",
			`      $ boundary host-sets read -id hsst_1234567890`,
			"",
			"  Please see the host-sets subcommand help for detailed usage information.",
		})
	case "create":
		return base.WrapForHelpText([]string{
			"Usage: boundary host-sets create [type] [sub command] [options] [args]",
			"",
			"  This command allows create operations on Boundary host-set resources. Example:",
			"",
			"    Create a static-type host-set:",
			"",
			`      $ boundary host-sets create static -name prodops -description "For ProdOps usage"`,
			"",
			"  Please see the typed subcommand help for detailed usage information.",
		})
	case "update":
		return base.WrapForHelpText([]string{
			"Usage: boundary host-sets update [type] [sub command] [options] [args]",
			"",
			"  This command allows update operations on Boundary host-set resources. Example:",
			"",
			"    Update a static-type host-set:",
			"",
			`      $ boundary host-sets update static -id hsst_1234567890 -name devops -description "For DevOps usage"`,
			"",
			"  Please see the typed subcommand help for detailed usage information.",
		})
	default:
		return helpMap[c.Func]() + c.Flags().Help()
	}
}

func (c *Command) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)

	f := set.NewFlagSet("Command Options")

	if len(flagsMap[c.Func]) > 0 {
		common.PopulateCommonFlags(c.Command, f, resource.HostSet.String(), flagsMap[c.Func])
	}

	f.StringVar(&base.StringVar{
		Name:   "host-catalog-id",
		Target: &c.flagHostCatalogId,
		Usage:  "The host-catalog resource in which to create or update the host-set resource",
	})

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

	client, err := c.Client()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error creating API client: %s", err.Error()))
		return 2
	}

	var opts []hostsets.Option

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

	hostsetClient := hostsets.NewClient(client)

	var existed bool
	var set *hostsets.HostSet
	var listedSets []*hostsets.HostSet
	var apiErr *api.Error

	switch c.Func {
	case "read":
		set, apiErr, err = hostsetClient.Read(c.Context, c.flagHostCatalogId, c.FlagId, opts...)
	case "delete":
		existed, apiErr, err = hostsetClient.Delete(c.Context, c.flagHostCatalogId, c.FlagId, opts...)
	case "list":
		listedSets, apiErr, err = hostsetClient.List(c.Context, c.flagHostCatalogId, opts...)
	}

	plural := "host set"
	if c.Func == "list" {
		plural = "host sets"
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
		switch base.Format(c.UI) {
		case "json":
			if len(listedSets) == 0 {
				c.UI.Output("null")
				return 0
			}
			b, err := base.JsonFormatter{}.Format(listedSets)
			if err != nil {
				c.UI.Error(fmt.Errorf("Error formatting as JSON: %w", err).Error())
				return 1
			}
			c.UI.Output(string(b))

		case "table":
			if len(listedSets) == 0 {
				c.UI.Output("No host sets found")
				return 0
			}
			var output []string
			output = []string{
				"",
				"Host Set information:",
			}
			for i, m := range listedSets {
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

	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(generateHostSetTableOutput(set))
	case "json":
		b, err := base.JsonFormatter{}.Format(set)
		if err != nil {
			c.UI.Error(fmt.Errorf("Error formatting as JSON: %w", err).Error())
			return 1
		}
		c.UI.Output(string(b))
	}

	return 0
}
