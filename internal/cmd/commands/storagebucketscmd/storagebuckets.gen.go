// Code generated by "make cli"; DO NOT EDIT.
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package storagebucketscmd

import (
	"errors"
	"fmt"
	"sync"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/storagebuckets"
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

	synopsisStr := "storage bucket"

	return common.SynopsisFunc(c.Func, synopsisStr)
}

func (c *Command) Help() string {
	initFlags()

	var helpStr string
	helpMap := common.HelpMap("storage bucket")

	switch c.Func {

	case "create":
		helpStr = helpMap[c.Func]() + c.Flags().Help()

	case "update":
		helpStr = helpMap[c.Func]() + c.Flags().Help()

	case "read":
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

	"create": {"scope-id", "name", "description", "plugin-id", "plugin-name", "attributes", "attr", "string-attr", "bool-attr", "num-attr", "secrets", "secret", "string-secret", "bool-secret", "num-secret"},

	"update": {"id", "name", "description", "version", "attributes", "attr", "string-attr", "bool-attr", "num-attr", "secrets", "secret", "string-secret", "bool-secret", "num-secret"},

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
	common.PopulateCommonFlags(c.Command, f, "storage bucket", flagsMap, c.Func)

	f = set.NewFlagSet("Attribute Options")
	attrsInput := common.CombinedSliceFlagValuePopulationInput{
		FlagSet:                          f,
		FlagNames:                        flagsMap[c.Func],
		FullPopulationFlag:               &c.FlagAttributes,
		FullPopulationInputName:          "attributes",
		PiecewisePopulationFlag:          &c.FlagAttrs,
		PiecewisePopulationInputBaseName: "attr",
	}
	common.PopulateCombinedSliceFlagValue(attrsInput)

	f = set.NewFlagSet("Secrets Options")
	scrtsInput := common.CombinedSliceFlagValuePopulationInput{
		FlagSet:                          f,
		FlagNames:                        flagsMap[c.Func],
		FullPopulationFlag:               &c.FlagSecrets,
		FullPopulationInputName:          "secrets",
		PiecewisePopulationFlag:          &c.FlagScrts,
		PiecewisePopulationInputBaseName: "secret",
	}
	common.PopulateCombinedSliceFlagValue(scrtsInput)

	extraFlagsFunc(c, set, f)

	return set
}

func (c *Command) Run(args []string) int {
	initFlags()

	switch c.Func {
	case "":
		return cli.RunResultHelp

	}

	c.plural = "storage bucket"
	switch c.Func {
	case "list":
		c.plural = "storage buckets"
	}

	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.PrintCliError(err)
		return base.CommandUserError
	}

	if strutil.StrListContains(flagsMap[c.Func], "id") && c.FlagId == "" {
		c.PrintCliError(errors.New("ID is required but not passed in via -id"))
		return base.CommandUserError
	}

	if c.FlagAttributes != "" && len(c.FlagAttrs) > 0 {
		c.PrintCliError(errors.New("-attributes flag cannot be used along with the following flags: attr, bool-attr, num-attr, string-attr"))
		return base.CommandUserError
	}

	if c.FlagSecrets != "" && len(c.FlagScrts) > 0 {
		c.PrintCliError(errors.New("-secrets flag cannot be used along with the following flags: secret, bool-secret, num-secret, string-secret"))
		return base.CommandUserError
	}

	var opts []storagebuckets.Option

	if strutil.StrListContains(flagsMap[c.Func], "scope-id") {
		switch c.Func {

		case "create":
			if c.FlagScopeId == "" {
				c.PrintCliError(errors.New("Scope ID must be passed in via -scope-id or BOUNDARY_SCOPE_ID"))
				return base.CommandUserError
			}

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
	storagebucketsClient := storagebuckets.NewClient(client)

	switch c.FlagName {
	case "":
	case "null":
		opts = append(opts, storagebuckets.DefaultName())
	default:
		opts = append(opts, storagebuckets.WithName(c.FlagName))
	}

	switch c.FlagDescription {
	case "":
	case "null":
		opts = append(opts, storagebuckets.DefaultDescription())
	default:
		opts = append(opts, storagebuckets.WithDescription(c.FlagDescription))
	}

	switch c.FlagRecursive {
	case true:
		opts = append(opts, storagebuckets.WithRecursive(true))
	}

	if c.FlagFilter != "" {
		opts = append(opts, storagebuckets.WithFilter(c.FlagFilter))
	}

	switch c.FlagPluginId {
	case "":
	default:
		opts = append(opts, storagebuckets.WithPluginId(c.FlagPluginId))
	}
	switch c.FlagPluginName {
	case "":
	default:
		opts = append(opts, storagebuckets.WithPluginName(c.FlagPluginName))
	}

	var version uint32

	switch c.Func {

	case "update":
		switch c.FlagVersion {
		case 0:
			opts = append(opts, storagebuckets.WithAutomaticVersioning(true))
		default:
			version = uint32(c.FlagVersion)
		}

	}

	if err := common.HandleAttributeFlags(
		c.Command,
		"attr",
		c.FlagAttributes,
		c.FlagAttrs,
		func() {
			opts = append(opts, storagebuckets.DefaultAttributes())
		},
		func(in map[string]interface{}) {
			opts = append(opts, storagebuckets.WithAttributes(in))
		}); err != nil {
		c.PrintCliError(fmt.Errorf("Error evaluating attribute flags to: %s", err.Error()))
		return base.CommandCliError
	}

	if err := common.HandleAttributeFlags(
		c.Command,
		"secret",
		c.FlagSecrets,
		c.FlagScrts,
		func() {
			opts = append(opts, storagebuckets.DefaultSecrets())
		},
		func(in map[string]interface{}) {
			opts = append(opts, storagebuckets.WithSecrets(in))
		}); err != nil {
		c.PrintCliError(fmt.Errorf("Error evaluating secret flags to: %s", err.Error()))
		return base.CommandCliError
	}

	if ok := extraFlagsHandlingFunc(c, f, &opts); !ok {
		return base.CommandUserError
	}

	var resp *api.Response
	var item *storagebuckets.StorageBucket

	var items []*storagebuckets.StorageBucket

	var createResult *storagebuckets.StorageBucketCreateResult

	var updateResult *storagebuckets.StorageBucketUpdateResult

	var readResult *storagebuckets.StorageBucketReadResult

	var deleteResult *storagebuckets.StorageBucketDeleteResult

	var listResult *storagebuckets.StorageBucketListResult

	switch c.Func {

	case "create":
		createResult, err = storagebucketsClient.Create(c.Context, c.FlagScopeId, opts...)
		if exitCode := c.checkFuncError(err); exitCode > 0 {
			return exitCode
		}
		resp = createResult.GetResponse()
		item = createResult.GetItem()

	case "update":
		updateResult, err = storagebucketsClient.Update(c.Context, c.FlagId, version, opts...)
		if exitCode := c.checkFuncError(err); exitCode > 0 {
			return exitCode
		}
		resp = updateResult.GetResponse()
		item = updateResult.GetItem()

	case "read":
		readResult, err = storagebucketsClient.Read(c.Context, c.FlagId, opts...)
		if exitCode := c.checkFuncError(err); exitCode > 0 {
			return exitCode
		}
		resp = readResult.GetResponse()
		item = readResult.GetItem()

	case "delete":
		deleteResult, err = storagebucketsClient.Delete(c.Context, c.FlagId, opts...)
		if exitCode := c.checkFuncError(err); exitCode > 0 {
			return exitCode
		}
		resp = deleteResult.GetResponse()

	case "list":
		listResult, err = storagebucketsClient.List(c.Context, c.FlagScopeId, opts...)
		if exitCode := c.checkFuncError(err); exitCode > 0 {
			return exitCode
		}
		resp = listResult.GetResponse()
		items = listResult.GetItems()

	}

	resp, item, items, err = executeExtraActions(c, resp, item, items, err, storagebucketsClient, version, opts)
	if exitCode := c.checkFuncError(err); exitCode > 0 {
		return exitCode
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
			if ok := c.PrintJsonItem(resp); !ok {
				return base.CommandCliError
			}

		case "table":
			c.UI.Output("The delete operation completed successfully.")
		}

		return base.CommandSuccess

	case "list":
		switch base.Format(c.UI) {
		case "json":
			if ok := c.PrintJsonItems(resp); !ok {
				return base.CommandCliError
			}

		case "table":
			c.UI.Output(c.printListTable(items))
		}

		return base.CommandSuccess

	}

	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(printItemTable(item, resp))

	case "json":
		if ok := c.PrintJsonItem(resp); !ok {
			return base.CommandCliError
		}
	}

	return base.CommandSuccess
}

func (c *Command) checkFuncError(err error) int {
	if err == nil {
		return 0
	}
	if apiErr := api.AsServerError(err); apiErr != nil {
		c.PrintApiError(apiErr, fmt.Sprintf("Error from controller when performing %s on %s", c.Func, c.plural))
		return base.CommandApiError
	}
	c.PrintCliError(fmt.Errorf("Error trying to %s %s: %s", c.Func, c.plural, err.Error()))
	return base.CommandCliError
}

var (
	flagsOnce = new(sync.Once)

	extraActionsFlagsMapFunc = func() map[string][]string { return nil }
	extraSynopsisFunc        = func(*Command) string { return "" }
	extraFlagsFunc           = func(*Command, *base.FlagSets, *base.FlagSet) {}
	extraFlagsHandlingFunc   = func(*Command, *base.FlagSets, *[]storagebuckets.Option) bool { return true }
	executeExtraActions      = func(_ *Command, inResp *api.Response, inItem *storagebuckets.StorageBucket, inItems []*storagebuckets.StorageBucket, inErr error, _ *storagebuckets.Client, _ uint32, _ []storagebuckets.Option) (*api.Response, *storagebuckets.StorageBucket, []*storagebuckets.StorageBucket, error) {
		return inResp, inItem, inItems, inErr
	}
	printCustomActionOutput = func(*Command) (bool, error) { return false, nil }
)
