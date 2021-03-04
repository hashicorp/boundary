// Code generated by "make api"; DO NOT EDIT.
package rolescmd

import (
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/roles"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/common"
	"github.com/hashicorp/boundary/sdk/strutil"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

func initFlags() {
	flagsOnce.Do(func() {
		extraFlags := extraActionsFlagsMapFunc()
		for k, v := range extraFlags {
			flagsMap[k] = append(flagsMap[k], v...)
		}
	})
}

var (
	_ cli.Command             = (*Command)(nil)
	_ cli.CommandAutocomplete = (*Command)(nil)
)

type Command struct {
	*base.Command

	Func string

	plural string

	extraCmdVars
}

func (c *Command) AutocompleteArgs() complete.Predictor {
	initFlags()
	return complete.PredictAnything
}

func (c *Command) AutocompleteFlags() complete.Flags {
	initFlags()
	return c.Flags().Completions()
}

func (c *Command) Synopsis() string {
	if extra := extraSynopsisFunc(c); extra != "" {
		return extra
	}

	synopsisStr := "role"

	return common.SynopsisFunc(c.Func, synopsisStr)
}

func (c *Command) Help() string {
	initFlags()

	var helpStr string
	helpMap := common.HelpMap("role")

	switch c.Func {

	case "create":
		helpStr = helpMap[c.Func]() + c.Flags().Help()

	case "read":
		helpStr = helpMap[c.Func]() + c.Flags().Help()

	case "update":
		helpStr = helpMap[c.Func]() + c.Flags().Help()

	case "delete":
		helpStr = helpMap[c.Func]() + c.Flags().Help()

	case "list":
		helpStr = helpMap[c.Func]() + c.Flags().Help()

	default:

		helpStr = c.extraHelpFunc(helpMap)

	}

	// Keep linter from complaining if we don't actually generate code using it
	_ = helpMap
	return helpStr
}

var flagsMap = map[string][]string{

	"create": {"scope-id", "name", "description"},

	"read": {"id"},

	"update": {"id", "name", "description", "version"},

	"delete": {"id"},

	"list": {"scope-id", "filter", "recursive"},
}

func (c *Command) Flags() *base.FlagSets {
	if len(flagsMap[c.Func]) == 0 {
		return c.FlagSet(base.FlagSetNone)
	}

	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)
	f := set.NewFlagSet("Command Options")
	common.PopulateCommonFlags(c.Command, f, "role", flagsMap[c.Func])

	extraFlagsFunc(c, set, f)

	return set
}

func (c *Command) Run(args []string) int {
	initFlags()

	switch c.Func {
	case "":
		return cli.RunResultHelp
	}

	c.plural = "role"
	switch c.Func {
	case "list":
		c.plural = "roles"
	}

	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.PrintCliError(err)
		return 3
	}

	if strutil.StrListContains(flagsMap[c.Func], "id") && c.FlagId == "" {
		c.PrintCliError(errors.New("ID is required but not passed in via -id"))
		return 3
	}

	var opts []roles.Option

	if strutil.StrListContains(flagsMap[c.Func], "scope-id") {
		switch c.Func {

		case "create":
			if c.FlagScopeId == "" {
				c.PrintCliError(errors.New("Scope ID must be passed in via -scope-id or BOUNDARY_SCOPE_ID"))
				return 3
			}

		case "list":
			if c.FlagScopeId == "" {
				c.PrintCliError(errors.New("Scope ID must be passed in via -scope-id or BOUNDARY_SCOPE_ID"))
				return 3
			}

		}
	}

	client, err := c.Client()
	if err != nil {
		c.PrintCliError(fmt.Errorf("Error creating API client: %s", err.Error()))
		return 2
	}
	rolesClient := roles.NewClient(client)

	switch c.FlagName {
	case "":
	case "null":
		opts = append(opts, roles.DefaultName())
	default:
		opts = append(opts, roles.WithName(c.FlagName))
	}

	switch c.FlagDescription {
	case "":
	case "null":
		opts = append(opts, roles.DefaultDescription())
	default:
		opts = append(opts, roles.WithDescription(c.FlagDescription))
	}

	switch c.FlagRecursive {
	case true:
		opts = append(opts, roles.WithRecursive(true))
	}

	if c.FlagFilter != "" {
		opts = append(opts, roles.WithFilter(c.FlagFilter))
	}

	var version uint32

	switch c.Func {

	case "update":
		switch c.FlagVersion {
		case 0:
			opts = append(opts, roles.WithAutomaticVersioning(true))
		default:
			version = uint32(c.FlagVersion)
		}

	case "add-grants":
		switch c.FlagVersion {
		case 0:
			opts = append(opts, roles.WithAutomaticVersioning(true))
		default:
			version = uint32(c.FlagVersion)
		}

	case "remove-grants":
		switch c.FlagVersion {
		case 0:
			opts = append(opts, roles.WithAutomaticVersioning(true))
		default:
			version = uint32(c.FlagVersion)
		}

	case "set-grants":
		switch c.FlagVersion {
		case 0:
			opts = append(opts, roles.WithAutomaticVersioning(true))
		default:
			version = uint32(c.FlagVersion)
		}

	case "add-principals":
		switch c.FlagVersion {
		case 0:
			opts = append(opts, roles.WithAutomaticVersioning(true))
		default:
			version = uint32(c.FlagVersion)
		}

	case "remove-principals":
		switch c.FlagVersion {
		case 0:
			opts = append(opts, roles.WithAutomaticVersioning(true))
		default:
			version = uint32(c.FlagVersion)
		}

	case "set-principals":
		switch c.FlagVersion {
		case 0:
			opts = append(opts, roles.WithAutomaticVersioning(true))
		default:
			version = uint32(c.FlagVersion)
		}

	}

	if ok := extraFlagsHandlingFunc(c, &opts); !ok {
		return 3
	}

	existed := true

	var result api.GenericResult

	var listResult api.GenericListResult

	switch c.Func {

	case "create":
		result, err = rolesClient.Create(c.Context, c.FlagScopeId, opts...)

	case "read":
		result, err = rolesClient.Read(c.Context, c.FlagId, opts...)

	case "update":
		result, err = rolesClient.Update(c.Context, c.FlagId, version, opts...)

	case "delete":
		_, err = rolesClient.Delete(c.Context, c.FlagId, opts...)
		if apiErr := api.AsServerError(err); apiErr != nil && apiErr.Response().StatusCode() == http.StatusNotFound {
			existed = false
			err = nil
		}

	case "list":
		listResult, err = rolesClient.List(c.Context, c.FlagScopeId, opts...)

	}

	result, err = executeExtraActions(c, result, err, rolesClient, version, opts)

	if err != nil {
		if apiErr := api.AsServerError(err); apiErr != nil {
			c.PrintApiError(apiErr, fmt.Sprintf("Error from controller when performing %s on %s", c.Func, c.plural))
			return 1
		}
		c.PrintCliError(fmt.Errorf("Error trying to %s %s: %s", c.Func, c.plural, err.Error()))
		return 2
	}

	output, err := printCustomActionOutput(c)
	if err != nil {
		c.PrintCliError(err)
		return 3
	}
	if output {
		return 0
	}

	switch c.Func {

	case "delete":
		switch base.Format(c.UI) {
		case "json":
			c.UI.Output(fmt.Sprintf("{ \"existed\": %t }", existed))

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
		listedItems := listResult.GetItems().([]*roles.Role)
		switch base.Format(c.UI) {
		case "json":
			switch {

			case len(listedItems) == 0:
				c.UI.Output("null")

			default:
				items := make([]interface{}, len(listedItems))
				for i, v := range listedItems {
					items[i] = v
				}
				if ok := c.PrintJsonItems(listResult, items); !ok {
					return 2
				}
			}

		case "table":
			c.UI.Output(c.printListTable(listedItems))
		}

		return 0

	}

	item := result.GetItem().(*roles.Role)
	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(printItemTable(item))

	case "json":
		if ok := c.PrintJsonItem(result, item); !ok {
			return 2
		}
	}

	return 0
}

var (
	flagsOnce = new(sync.Once)

	extraActionsFlagsMapFunc = func() map[string][]string { return nil }
	extraSynopsisFunc        = func(*Command) string { return "" }
	extraFlagsFunc           = func(*Command, *base.FlagSets, *base.FlagSet) {}
	extraFlagsHandlingFunc   = func(*Command, *[]roles.Option) bool { return true }
	executeExtraActions      = func(_ *Command, inResult api.GenericResult, inErr error, _ *roles.Client, _ uint32, _ []roles.Option) (api.GenericResult, error) {
		return inResult, inErr
	}
	printCustomActionOutput = func(*Command) (bool, error) { return false, nil }
)
