// Code generated by "make api"; DO NOT EDIT.
package hostscmd

import (
	"errors"
	"fmt"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/hosts"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/common"
	"github.com/hashicorp/boundary/sdk/strutil"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

func initStaticFlags() {
	flagsOnce.Do(func() {
		extraFlags := extraStaticActionsFlagsMapFunc()
		for k, v := range extraFlags {
			flagsStaticMap[k] = append(flagsStaticMap[k], v...)
		}
	})
}

var (
	_ cli.Command             = (*StaticCommand)(nil)
	_ cli.CommandAutocomplete = (*StaticCommand)(nil)
)

type StaticCommand struct {
	*base.Command

	Func string

	plural string

	extraStaticCmdVars
}

func (c *StaticCommand) AutocompleteArgs() complete.Predictor {
	initStaticFlags()
	return complete.PredictAnything
}

func (c *StaticCommand) AutocompleteFlags() complete.Flags {
	initStaticFlags()
	return c.Flags().Completions()
}

func (c *StaticCommand) Synopsis() string {
	if extra := extraStaticSynopsisFunc(c); extra != "" {
		return extra
	}

	synopsisStr := "host"

	synopsisStr = fmt.Sprintf("%s %s", "static-type", synopsisStr)

	return common.SynopsisFunc(c.Func, synopsisStr)
}

func (c *StaticCommand) Help() string {
	initStaticFlags()

	var helpStr string
	helpMap := common.HelpMap("host")

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
	common.PopulateCommonFlags(c.Command, f, "static-type host", flagsStaticMap, c.Func)

	extraStaticFlagsFunc(c, set, f)

	return set
}

func (c *StaticCommand) Run(args []string) int {
	initStaticFlags()

	switch c.Func {
	case "":
		return cli.RunResultHelp
	}

	c.plural = "static-type host"
	switch c.Func {
	case "list":
		c.plural = "static-type hosts"
	}

	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.PrintCliError(err)
		return base.CommandUserError
	}

	if strutil.StrListContains(flagsStaticMap[c.Func], "id") && c.FlagId == "" {
		c.PrintCliError(errors.New("ID is required but not passed in via -id"))
		return base.CommandUserError
	}

	var opts []hosts.Option

	if strutil.StrListContains(flagsStaticMap[c.Func], "host-catalog-id") {
		switch c.Func {
		case "create":
			if c.FlagHostCatalogId == "" {
				c.PrintCliError(errors.New("HostCatalog ID must be passed in via -host-catalog-id or BOUNDARY_HOST_CATALOG_ID"))
				return base.CommandUserError
			}
		}
	}

	client, err := c.Client()
	if err != nil {
		c.PrintCliError(fmt.Errorf("Error creating API client: %s", err.Error()))
		return base.CommandCliError
	}
	hostsClient := hosts.NewClient(client)

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

	if c.FlagFilter != "" {
		opts = append(opts, hosts.WithFilter(c.FlagFilter))
	}

	var version uint32

	switch c.Func {
	case "update":
		switch c.FlagVersion {
		case 0:
			opts = append(opts, hosts.WithAutomaticVersioning(true))
		default:
			version = uint32(c.FlagVersion)
		}
	}

	if ok := extraStaticFlagsHandlingFunc(c, f, &opts); !ok {
		return base.CommandUserError
	}

	var result api.GenericResult

	switch c.Func {

	case "create":
		result, err = hostsClient.Create(c.Context, c.FlagHostCatalogId, opts...)

	case "update":
		result, err = hostsClient.Update(c.Context, c.FlagId, version, opts...)

	}

	result, err = executeExtraStaticActions(c, result, err, hostsClient, version, opts)

	if err != nil {
		if apiErr := api.AsServerError(err); apiErr != nil {
			c.PrintApiError(apiErr, fmt.Sprintf("Error from controller when performing %s on %s", c.Func, c.plural))
			return base.CommandApiError
		}
		c.PrintCliError(fmt.Errorf("Error trying to %s %s: %s", c.Func, c.plural, err.Error()))
		return base.CommandCliError
	}

	output, err := printCustomStaticActionOutput(c)
	if err != nil {
		c.PrintCliError(err)
		return base.CommandUserError
	}
	if output {
		return base.CommandSuccess
	}

	switch c.Func {
	}

	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(printItemTable(result))

	case "json":
		if ok := c.PrintJsonItem(result); !ok {
			return base.CommandCliError
		}
	}

	return base.CommandSuccess
}

var (
	extraStaticActionsFlagsMapFunc = func() map[string][]string { return nil }
	extraStaticSynopsisFunc        = func(*StaticCommand) string { return "" }
	extraStaticFlagsFunc           = func(*StaticCommand, *base.FlagSets, *base.FlagSet) {}
	extraStaticFlagsHandlingFunc   = func(*StaticCommand, *base.FlagSets, *[]hosts.Option) bool { return true }
	executeExtraStaticActions      = func(_ *StaticCommand, inResult api.GenericResult, inErr error, _ *hosts.Client, _ uint32, _ []hosts.Option) (api.GenericResult, error) {
		return inResult, inErr
	}
	printCustomStaticActionOutput = func(*StaticCommand) (bool, error) { return false, nil }
)
