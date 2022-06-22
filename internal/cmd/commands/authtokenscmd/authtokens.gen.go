// Code generated by "make cli"; DO NOT EDIT.
package authtokenscmd

import (
	"errors"
	"fmt"
	"sync"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/common"
	"github.com/hashicorp/go-secure-stdlib/strutil"
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

	"list": {"scope-id", "filter", "recursive"},
}

func (c *Command) Flags() *base.FlagSets {
	if len(flagsMap[c.Func]) == 0 {
		return c.FlagSet(base.FlagSetNone)
	}

	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)
	f := set.NewFlagSet("Command Options")
	common.PopulateCommonFlags(c.Command, f, "auth token", flagsMap, c.Func)

	extraFlagsFunc(c, set, f)

	return set
}

func (c *Command) Run(args []string) int {
	initFlags()

	switch c.Func {
	case "":
		return cli.RunResultHelp

	case "create":
		return cli.RunResultHelp

	case "update":
		return cli.RunResultHelp

	}

	c.plural = "auth token"
	switch c.Func {
	case "list":
		c.plural = "auth tokens"
	}

	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.PrintCliError(err)
		return base.CommandUserError
	}

	var opts []authtokens.Option

	if strutil.StrListContains(flagsMap[c.Func], "scope-id") {
		switch c.Func {

		case "list":
			if c.FlagScopeId == "" {
				c.PrintCliError(errors.New("Scope ID must be passed in via -scope-id or BOUNDARY_SCOPE_ID"))
				return base.CommandUserError
			}

		}
	}

	client, err := c.Client()
	if c.WrapperCleanupFunc != nil {
		defer func() {
			if err := c.WrapperCleanupFunc(); err != nil {
				c.PrintCliError(fmt.Errorf("Error cleaning kms wrapper: %w", err))
			}
		}()
	}
	if err != nil {
		c.PrintCliError(fmt.Errorf("Error creating API client: %w", err))
		return base.CommandCliError
	}
	authtokensClient := authtokens.NewClient(client)

	switch c.FlagRecursive {
	case true:
		opts = append(opts, authtokens.WithRecursive(true))
	}

	if c.FlagFilter != "" {
		opts = append(opts, authtokens.WithFilter(c.FlagFilter))
	}

	var version uint32

	if ok := extraFlagsHandlingFunc(c, f, &opts); !ok {
		return base.CommandUserError
	}

	var result api.GenericResult

	var listResult api.GenericListResult

	switch c.Func {

	case "read":
		result, err = authtokensClient.Read(c.Context, c.FlagId, opts...)

	case "delete":
		result, err = authtokensClient.Delete(c.Context, c.FlagId, opts...)

	case "list":
		listResult, err = authtokensClient.List(c.Context, c.FlagScopeId, opts...)

	}

	result, err = executeExtraActions(c, result, err, authtokensClient, version, opts)

	if err != nil {
		if apiErr := api.AsServerError(err); apiErr != nil {
			var opts []base.Option

			c.PrintApiError(apiErr, fmt.Sprintf("Error from controller when performing %s on %s", c.Func, c.plural), opts...)
			return base.CommandApiError
		}
		c.PrintCliError(fmt.Errorf("Error trying to %s %s: %s", c.Func, c.plural, err.Error()))
		return base.CommandCliError
	}

	output, err := printCustomActionOutput(c)
	if err != nil {
		c.PrintCliError(err)
		return base.CommandUserError
	}
	if output {
		return base.CommandSuccess
	}

	switch c.Func {

	case "delete":
		switch base.Format(c.UI) {
		case "json":
			if ok := c.PrintJsonItem(result); !ok {
				return base.CommandCliError
			}

		case "table":
			c.UI.Output("The delete operation completed successfully.")
		}

		return base.CommandSuccess

	case "list":
		switch base.Format(c.UI) {
		case "json":
			if ok := c.PrintJsonItems(listResult); !ok {
				return base.CommandCliError
			}

		case "table":
			listedItems := listResult.GetItems().([]*authtokens.AuthToken)
			c.UI.Output(c.printListTable(listedItems))
		}

		return base.CommandSuccess

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
	flagsOnce = new(sync.Once)

	extraActionsFlagsMapFunc = func() map[string][]string { return nil }
	extraSynopsisFunc        = func(*Command) string { return "" }
	extraFlagsFunc           = func(*Command, *base.FlagSets, *base.FlagSet) {}
	extraFlagsHandlingFunc   = func(*Command, *base.FlagSets, *[]authtokens.Option) bool { return true }
	executeExtraActions      = func(_ *Command, inResult api.GenericResult, inErr error, _ *authtokens.Client, _ uint32, _ []authtokens.Option) (api.GenericResult, error) {
		return inResult, inErr
	}
	printCustomActionOutput = func(*Command) (bool, error) { return false, nil }
)
