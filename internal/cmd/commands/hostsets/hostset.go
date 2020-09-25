package hostsets

import (
	"fmt"
	"net/http"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/hostsets"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/common"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/sdk/strutil"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var _ cli.Command = (*Command)(nil)
var _ cli.CommandAutocomplete = (*Command)(nil)

type Command struct {
	*base.Command

	Func string

	flagHostCatalogId string
	flagHosts         []string
}

func (c *Command) Synopsis() string {
	switch c.Func {
	case "create":
		return "Create host-set resources within Boundary"
	case "update":
		return "Update host-set resources within Boundary"
	case "add-hosts":
		return "Add hosts to the specified host-set"
	case "remove-hosts":
		return "Remove hosts from the specified host-set"
	case "set-hosts":
		return "Set the full contents of the hosts on the specified host-set"
	default:
		return common.SynopsisFunc(c.Func, "host-set")
	}
}

var flagsMap = map[string][]string{
	"read":         {"id"},
	"delete":       {"id"},
	"list":         {"host-catalog-id"},
	"add-hosts":    {"id", "host", "version"},
	"set-hosts":    {"id", "host", "version"},
	"remove-hosts": {"id", "host", "version"},
}

func (c *Command) Help() string {
	helpMap := common.HelpMap("host-set")
	var helpStr string
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
		helpStr = base.WrapForHelpText([]string{
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
		helpStr = base.WrapForHelpText([]string{
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
	case "add-hosts":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary host-sets add-hosts [sub command] [options] [args]",
			"",
			"  This command allows adding hosts to host-set resources, if the types match and the operation is allowed by the given host-set type. Example:",
			"",
			"    Add static-type hosts to a static-type host-set:",
			"",
			`      $ boundary host-sets add-hosts -id hsst_1234567890 -host hst_1234567890 -host hst_0987654321`,
		})
	case "remove-hosts":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary host-sets remove-hosts [sub command] [options] [args]",
			"",
			"  This command allows removing hosts from host-set resources, if the types match and the operation is allowed by the given host-set type. Example:",
			"",
			"    Remove static-type hosts from a static-type host-set:",
			"",
			`      $ boundary host-sets remove-hosts -id hsst_1234567890 -host hst_0987654321`,
		})
	case "set-hosts":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary host-sets set-hosts [sub command] [options] [args]",
			"",
			"  This command allows setting the complete set of hosts on host-set resources, if the types match and the operation is allowed by the given host-set type. Example:",
			"",
			"    Set the complete set of static-type hosts on a static-type host-set:",
			"",
			`      $ boundary host-sets remove-hosts -id hsst_1234567890 -host hst_1234567890`,
		})
	default:
		helpStr = helpMap[c.Func]()
	}
	return helpStr + c.Flags().Help()
}

func (c *Command) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)

	f := set.NewFlagSet("Command Options")
	common.PopulateCommonFlags(c.Command, f, resource.HostSet.String(), flagsMap[c.Func])

	for _, name := range flagsMap[c.Func] {
		switch name {
		case "host-catalog-id":
			f.StringVar(&base.StringVar{
				Name:   "host-catalog-id",
				Target: &c.flagHostCatalogId,
				Usage:  "The host-catalog resource in which to list host-set resources",
			})
		case "host":
			f.StringSliceVar(&base.StringSliceVar{
				Name:   "host",
				Target: &c.flagHosts,
				Usage:  "The hosts to add, remove, or set. May be specified multiple times.",
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

	hosts := c.flagHosts
	switch c.Func {
	case "add-hosts", "remove-hosts":
		if len(c.flagHosts) == 0 {
			c.UI.Error("No hosts supplied via -host")
			return 1
		}

	case "set-hosts":
		switch len(c.flagHosts) {
		case 0:
			c.UI.Error("No hosts supplied via -host")
			return 1
		case 1:
			if c.flagHosts[0] == "null" {
				hosts = nil
			}
		}
	}

	// Perform check-and-set when needed
	var version uint32
	switch c.Func {
	case "add-hosts", "remove-hosts", "set-hosts":
		switch c.FlagVersion {
		case 0:
			opts = append(opts, hostsets.WithAutomaticVersioning(true))
		default:
			version = uint32(c.FlagVersion)
		}
	default:
		// The only other one that needs it is update, handled by the static
		// file
	}

	hostsetClient := hostsets.NewClient(client)

	existed := true
	var result api.GenericResult
	var listResult api.GenericListResult

	switch c.Func {
	case "read":
		result, err = hostsetClient.Read(c.Context, c.FlagId, opts...)
	case "delete":
		_, err = hostsetClient.Delete(c.Context, c.FlagId, opts...)
		if apiErr := api.AsServerError(err); apiErr != nil && apiErr.Status == int32(http.StatusNotFound) {
			existed = false
			err = nil
		}
	case "list":
		listResult, err = hostsetClient.List(c.Context, c.flagHostCatalogId, opts...)
	case "add-hosts":
		result, err = hostsetClient.AddHosts(c.Context, c.FlagId, version, hosts, opts...)
	case "remove-hosts":
		result, err = hostsetClient.RemoveHosts(c.Context, c.FlagId, version, hosts, opts...)
	case "set-hosts":
		result, err = hostsetClient.SetHosts(c.Context, c.FlagId, version, hosts, opts...)
	}

	plural := "host set"
	if c.Func == "list" {
		plural = "host sets"
	}
	if err != nil {
		if api.AsServerError(err) != nil {
			c.UI.Error(fmt.Sprintf("Error from controller when performing %s on %s: %s", c.Func, plural, err.Error()))
			return 1
		}
		c.UI.Error(fmt.Sprintf("Error trying to %s %s: %s", c.Func, plural, err.Error()))
		return 2
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
		listedSets := listResult.GetItems().([]*hostsets.HostSet)
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

	set := result.GetItem().(*hostsets.HostSet)
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
