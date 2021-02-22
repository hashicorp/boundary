package authtokenscmd

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authtokens"
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

	// Used for delete operations
	existed bool
	// Used in some output
	plural string
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

	synopsisStr := "auth token"

	return common.SynopsisFunc(c.Func, synopsisStr)
}

func (c *Command) Help() string {
	initFlags()

	var helpStr string
	helpMap := common.HelpMap("auth token")

	switch c.Func {

	case "read":
		helpStr = helpMap[c.Func]() + c.Flags().Help()

	case "delete":
		helpStr = helpMap[c.Func]() + c.Flags().Help()

	case "list":
		helpStr = helpMap[c.Func]() + c.Flags().Help()

	default:

		helpStr = helpMap["base"]()

	}

	// Keep linter from complaining if we don't actually generate code using it
	_ = helpMap
	return helpStr
}

var flagsMap = map[string][]string{

	"read": {"id"},

	"delete": {"id"},

	"list": {"scope-id", "recursive"},
}

func (c *Command) Flags() *base.FlagSets {
	if len(flagsMap[c.Func]) == 0 {
		return c.FlagSet(base.FlagSetNone)
	}

	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)
	f := set.NewFlagSet("Command Options")
	common.PopulateCommonFlags(c.Command, f, "auth token", flagsMap[c.Func])

	extraFlagsFunc(c, set, f)

	return set
}

func (c *Command) Run(args []string) int {
	initFlags()

	switch c.Func {
	case "":
		return cli.RunResultHelp
	}

	c.plural = "auth token"
	switch c.Func {
	case "list":
		c.plural = "auth tokens"
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

	var opts []authtokens.Option

	if strutil.StrListContains(flagsMap[c.Func], "scope-id") {
		switch c.Func {
		case "list":
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
	authtokensClient := authtokens.NewClient(client)

	switch c.FlagRecursive {
	case true:
		opts = append(opts, authtokens.WithRecursive(true))
	}

	var version uint32

	if ret := extraFlagsHandlingFunc(c, &opts); ret != 0 {
		return ret
	}

	c.existed = true
	var result api.GenericResult

	var listResult api.GenericListResult

	switch c.Func {

	case "read":
		result, err = authtokensClient.Read(c.Context, c.FlagId, opts...)

	case "delete":
		_, err = authtokensClient.Delete(c.Context, c.FlagId, opts...)
		if apiErr := api.AsServerError(err); apiErr != nil && apiErr.ResponseStatus() == http.StatusNotFound {
			c.existed = false
			err = nil
		}

	case "list":
		listResult, err = authtokensClient.List(c.Context, c.FlagScopeId, opts...)

	}

	result, err = executeExtraActions(c, result, err, authtokensClient, version, opts)

	if err != nil {
		if apiErr := api.AsServerError(err); apiErr != nil {
			c.UI.Error(fmt.Sprintf("Error from controller when performing %s on %s: %s", c.Func, c.plural, base.PrintApiError(apiErr)))
			return 1
		}
		c.UI.Error(fmt.Sprintf("Error trying to %s %s: %s", c.Func, c.plural, err.Error()))
		return 2
	}

	output, err := printCustomActionOutput(c)
	if err != nil {
		c.UI.Error(err.Error())
		return 1
	}
	if output {
		return 0
	}

	switch c.Func {

	case "delete":
		switch base.Format(c.UI) {
		case "json":
			c.UI.Output(fmt.Sprintf("{ \"existed\": %t }", c.existed))

		case "table":
			output := "The delete operation completed successfully"
			switch c.existed {
			case true:
				output += "."
			default:
				output += ", however the resource did not exist at the time."
			}
			c.UI.Output(output)
		}

		return 0

	case "list":
		listedItems := listResult.GetItems().([]*authtokens.AuthToken)
		switch base.Format(c.UI) {
		case "json":
			switch {

			case len(listedItems) == 0:
				c.UI.Output("null")

			default:
				b, err := base.JsonFormatter{}.Format(listedItems)
				if err != nil {
					c.UI.Error(fmt.Errorf("Error formatting as JSON: %w", err).Error())
					return 1
				}
				c.UI.Output(string(b))
			}

		case "table":
			c.UI.Output(c.printListTable(listedItems))
		}

		return 0

	}

	item := result.GetItem().(*authtokens.AuthToken)
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
	flagsOnce = new(sync.Once)

	extraActionsFlagsMapFunc = func() map[string][]string { return nil }
	extraSynopsisFunc        = func(*Command) string { return "" }
	extraFlagsFunc           = func(*Command, *base.FlagSets, *base.FlagSet) {}
	extraFlagsHandlingFunc   = func(*Command, *[]authtokens.Option) int { return 0 }
	executeExtraActions      = func(_ *Command, inResult api.GenericResult, inErr error, _ *authtokens.Client, _ uint32, _ []authtokens.Option) (api.GenericResult, error) {
		return inResult, inErr
	}
	printCustomActionOutput = func(*Command) (bool, error) { return false, nil }
)
