package hosts

import (
	"fmt"
	"net/textproto"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/hosts"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/common"
	"github.com/hashicorp/boundary/sdk/strutil"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var _ cli.Command = (*StaticCommand)(nil)
var _ cli.CommandAutocomplete = (*StaticCommand)(nil)

type StaticCommand struct {
	*base.Command

	Func string

	flagHostCatalogId string
	flagAddress       string
}

func (c *StaticCommand) Synopsis() string {
	return fmt.Sprintf("%s a static-type host within Boundary", textproto.CanonicalMIMEHeaderKey(c.Func))
}

var staticFlagsMap = map[string][]string{
	"create": {"host-catalog-id", "name", "description", "address"},
	"update": {"id", "name", "description", "version", "address"},
}

func (c *StaticCommand) Help() string {
	var info string
	switch c.Func {
	case "create":
		info = base.WrapForHelpText([]string{
			"Usage: boundary hosts static create [options] [args]",
			"",
			"  Create a static-type host. Example:",
			"",
			`    $ boundary hosts static create -name prodops -description "Static host for ProdOps" -address "127.0.0.1"`,
			"",
			"",
		})

	case "update":
		info = base.WrapForHelpText([]string{
			"Usage: boundary hosts static update [options] [args]",
			"",
			"  Update a static-type host given its ID. Example:",
			"",
			`    $ boundary hosts static update -id hst_1234567890 -name "devops" -description "Static host for DevOps" -address "10.20.30.40"`,
			"",
			"",
		})
	}
	return info + c.Flags().Help()
}

func (c *StaticCommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)

	f := set.NewFlagSet("Command Options")

	if len(staticFlagsMap[c.Func]) > 0 {
		common.PopulateCommonFlags(c.Command, f, "static-type host", staticFlagsMap[c.Func])
	}

	for _, name := range staticFlagsMap[c.Func] {
		switch name {
		case "host-catalog-id":
			f.StringVar(&base.StringVar{
				Name:   "host-catalog-id",
				Target: &c.flagHostCatalogId,
				Usage:  "The host-catalog resource in which to create or update the host resource",
			})
		}
	}

	f = set.NewFlagSet("Static Host Options")

	for _, name := range staticFlagsMap[c.Func] {
		switch name {
		case "address":
			f.StringVar(&base.StringVar{
				Name:   "address",
				Target: &c.flagAddress,
				Usage:  "The address of the host",
			})
		}
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
	if strutil.StrListContains(staticFlagsMap[c.Func], "host-catalog-id") && c.flagHostCatalogId == "" {
		c.UI.Error("Host Catalog ID must be passed in via -host-catalog-id")
		return 1
	}
	if c.Func == "create" && c.flagAddress == "" {
		c.UI.Error("Address must be passed in via -address")
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

	switch c.flagAddress {
	case "":
	case "null":
		opts = append(opts, hosts.DefaultStaticHostAddress())
	default:
		opts = append(opts, hosts.WithStaticHostAddress(c.flagAddress))
	}

	hostClient := hosts.NewClient(client)

	// Perform check-and-set when needed
	var version uint32
	switch c.Func {
	case "create":
		// These don't update so don't need the existing version
	default:
		switch c.FlagVersion {
		case 0:
			opts = append(opts, hosts.WithAutomaticVersioning(true))
		default:
			version = uint32(c.FlagVersion)
		}
	}

	var result api.GenericResult

	switch c.Func {
	case "create":
		result, err = hostClient.Create(c.Context, c.flagHostCatalogId, opts...)
	case "update":
		result, err = hostClient.Update(c.Context, c.FlagId, version, opts...)
	}

	plural := "static-type host"
	if err != nil {
		if api.AsServerError(err) != nil {
			c.UI.Error(fmt.Sprintf("Error from controller when performing %s on %s: %s", c.Func, plural, err.Error()))
			return 1
		}
		c.UI.Error(fmt.Sprintf("Error trying to %s %s: %s", c.Func, plural, err.Error()))
		return 2
	}

	host := result.GetItem().(*hosts.Host)
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
