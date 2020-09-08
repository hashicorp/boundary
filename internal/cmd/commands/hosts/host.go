package hosts

import (
	"fmt"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/hosts"
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
		return "Create host resources within Boundary"
	case "update":
		return "Update host resources within Boundary"
	default:
		return common.SynopsisFunc(c.Func, "host")
	}
}

var flagsMap = map[string][]string{
	"read":   {"id"},
	"delete": {"id"},
	"list":   {"host-catalog-id"},
}

func (c *Command) Help() string {
	helpMap := common.HelpMap("host")
	switch c.Func {
	case "":
		return base.WrapForHelpText([]string{
			"Usage: boundary hosts [sub command] [options] [args]",
			"",
			"  This command allows operations on Boundary host resources. Example:",
			"",
			"    Read a host:",
			"",
			`      $ boundary hosts read -id hst_1234567890`,
			"",
			"  Please see the hosts subcommand help for detailed usage information.",
		})
	case "create":
		return base.WrapForHelpText([]string{
			"Usage: boundary hosts create [type] [sub command] [options] [args]",
			"",
			"  This command allows create operations on Boundary host resources. Example:",
			"",
			"    Create a static-type host:",
			"",
			`      $ boundary hosts create static -name prodops -description "For ProdOps usage"`,
			"",
			"  Please see the typed subcommand help for detailed usage information.",
		})
	case "update":
		return base.WrapForHelpText([]string{
			"Usage: boundary hosts update [type] [sub command] [options] [args]",
			"",
			"  This command allows update operations on Boundary host resources. Example:",
			"",
			"    Update a static-type host:",
			"",
			`      $ boundary hosts update static -id hst_1234567890 -name devops -description "For DevOps usage"`,
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
		common.PopulateCommonFlags(c.Command, f, resource.Host.String(), flagsMap[c.Func])
	}

	for _, name := range flagsMap[c.Func] {
		switch name {
		case "host-catalog-id":
			f.StringVar(&base.StringVar{
				Name:   "host-catalog-id",
				Target: &c.flagHostCatalogId,
				Usage:  "The host-catalog resource in which to create or update the host resource",
			})
		}
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
	if strutil.StrListContains(flagsMap[c.Func], "host-catalog-id") && c.flagHostCatalogId == "" {
		c.UI.Error("Host Catalog ID must be passed in via -host-catalog-id")
		return 1
	}

	client, err := c.Client()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error creating API client: %s", err.Error()))
		return 2
	}

	var opts []hosts.Option

	switch c.FlagName {
	case "":
	case "null":
		opts = append(opts, hosts.DefaultName())
	default:
		opts = append(opts, hosts.WithName(c.FlagName))
	}

	switch c.FlagDescription {
	case "":
	case "null":
		opts = append(opts, hosts.DefaultDescription())
	default:
		opts = append(opts, hosts.WithDescription(c.FlagDescription))
	}

	hostClient := hosts.NewClient(client)

	var existed bool
	var host *hosts.Host
	var listedHosts []*hosts.Host
	var apiErr *api.Error

	switch c.Func {
	case "read":
		host, apiErr, err = hostClient.Read(c.Context, c.FlagId, opts...)
	case "delete":
		existed, apiErr, err = hostClient.Delete(c.Context, c.FlagId, opts...)
	case "list":
		listedHosts, apiErr, err = hostClient.List(c.Context, c.flagHostCatalogId, opts...)
	}

	plural := "host"
	if c.Func == "list" {
		plural = "hosts"
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
			if len(listedHosts) == 0 {
				c.UI.Output("null")
				return 0
			}
			b, err := base.JsonFormatter{}.Format(listedHosts)
			if err != nil {
				c.UI.Error(fmt.Errorf("Error formatting as JSON: %w", err).Error())
				return 1
			}
			c.UI.Output(string(b))

		case "table":
			if len(listedHosts) == 0 {
				c.UI.Output("No hosts found")
				return 0
			}
			var output []string
			output = []string{
				"",
				"Host information:",
			}
			for i, m := range listedHosts {
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
		c.UI.Output(generateHostTableOutput(host))
	case "json":
		b, err := base.JsonFormatter{}.Format(host)
		if err != nil {
			c.UI.Error(fmt.Errorf("Error formatting as JSON: %w", err).Error())
			return 1
		}
		c.UI.Output(string(b))
	}

	return 0
}
