// Code generated by "make api"; DO NOT EDIT.
package authmethodscmd

import (
	"errors"
	"fmt"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/common"
	"github.com/hashicorp/boundary/sdk/strutil"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

func initOidcFlags() {
	flagsOnce.Do(func() {
		extraFlags := extraOidcActionsFlagsMapFunc()
		for k, v := range extraFlags {
			flagsOidcMap[k] = append(flagsOidcMap[k], v...)
		}
	})
}

var (
	_ cli.Command             = (*OidcCommand)(nil)
	_ cli.CommandAutocomplete = (*OidcCommand)(nil)
)

type OidcCommand struct {
	*base.Command

	Func string

	plural string

	extraOidcCmdVars
}

func (c *OidcCommand) AutocompleteArgs() complete.Predictor {
	initOidcFlags()
	return complete.PredictAnything
}

func (c *OidcCommand) AutocompleteFlags() complete.Flags {
	initOidcFlags()
	return c.Flags().Completions()
}

func (c *OidcCommand) Synopsis() string {
	if extra := extraOidcSynopsisFunc(c); extra != "" {
		return extra
	}

	synopsisStr := "auth method"

	synopsisStr = fmt.Sprintf("%s %s", "oidc-type", synopsisStr)

	return common.SynopsisFunc(c.Func, synopsisStr)
}

func (c *OidcCommand) Help() string {
	initOidcFlags()

	var helpStr string
	helpMap := common.HelpMap("auth method")

	switch c.Func {
	default:

		helpStr = c.extraOidcHelpFunc(helpMap)
	}

	// Keep linter from complaining if we don't actually generate code using it
	_ = helpMap
	return helpStr
}

var flagsOidcMap = map[string][]string{

	"create": {"scope-id", "name", "description"},

	"update": {"id", "name", "description", "version"},
}

func (c *OidcCommand) Flags() *base.FlagSets {
	if len(flagsOidcMap[c.Func]) == 0 {
		return c.FlagSet(base.FlagSetNone)
	}

	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)
	f := set.NewFlagSet("Command Options")
	common.PopulateCommonFlags(c.Command, f, "oidc-type auth method", flagsOidcMap[c.Func])

	extraOidcFlagsFunc(c, set, f)

	return set
}

func (c *OidcCommand) Run(args []string) int {
	initOidcFlags()

	switch c.Func {
	case "":
		return cli.RunResultHelp
	}

	c.plural = "oidc-type auth method"
	switch c.Func {
	case "list":
		c.plural = "oidc-type auth methods"
	}

	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.PrintCliError(err)
		return base.CommandUserError
	}

	if strutil.StrListContains(flagsOidcMap[c.Func], "id") && c.FlagId == "" {
		c.PrintCliError(errors.New("ID is required but not passed in via -id"))
		return base.CommandUserError
	}

	var opts []authmethods.Option

	if strutil.StrListContains(flagsOidcMap[c.Func], "scope-id") {
		switch c.Func {
		case "create":
			if c.FlagScopeId == "" {
				c.PrintCliError(errors.New("Scope ID must be passed in via -scope-id or BOUNDARY_SCOPE_ID"))
				return base.CommandUserError
			}
		}
	}

	client, err := c.Client()
	if err != nil {
		c.PrintCliError(fmt.Errorf("Error creating API client: %s", err.Error()))
		return base.CommandCliError
	}
	authmethodsClient := authmethods.NewClient(client)

	switch c.FlagName {
	case "":
	case "null":
		opts = append(opts, authmethods.DefaultName())
	default:
		opts = append(opts, authmethods.WithName(c.FlagName))
	}

	switch c.FlagDescription {
	case "":
	case "null":
		opts = append(opts, authmethods.DefaultDescription())
	default:
		opts = append(opts, authmethods.WithDescription(c.FlagDescription))
	}

	switch c.FlagRecursive {
	case true:
		opts = append(opts, authmethods.WithRecursive(true))
	}

	if c.FlagFilter != "" {
		opts = append(opts, authmethods.WithFilter(c.FlagFilter))
	}

	var version uint32

	switch c.Func {

	case "update":
		switch c.FlagVersion {
		case 0:
			opts = append(opts, authmethods.WithAutomaticVersioning(true))
		default:
			version = uint32(c.FlagVersion)
		}

	case "change-state":
		switch c.FlagVersion {
		case 0:
			opts = append(opts, authmethods.WithAutomaticVersioning(true))
		default:
			version = uint32(c.FlagVersion)
		}

	}

	if ok := extraOidcFlagsHandlingFunc(c, &opts); !ok {
		return base.CommandUserError
	}

	var result api.GenericResult

	switch c.Func {

	case "create":
		result, err = authmethodsClient.Create(c.Context, "oidc", c.FlagScopeId, opts...)

	case "update":
		result, err = authmethodsClient.Update(c.Context, c.FlagId, version, opts...)

	}

	result, err = executeExtraOidcActions(c, result, err, authmethodsClient, version, opts)

	if err != nil {
		if apiErr := api.AsServerError(err); apiErr != nil {
			c.PrintApiError(apiErr, fmt.Sprintf("Error from controller when performing %s on %s", c.Func, c.plural))
			return base.CommandApiError
		}
		c.PrintCliError(fmt.Errorf("Error trying to %s %s: %s", c.Func, c.plural, err.Error()))
		return base.CommandCliError
	}

	output, err := printCustomOidcActionOutput(c)
	if err != nil {
		c.PrintCliError(err)
		return base.CommandUserError
	}
	if output {
		return base.CommandSuccess
	}

	switch c.Func {
	}

	item := result.GetItem().(*authmethods.AuthMethod)
	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(printItemTable(item))

	case "json":
		if ok := c.PrintJsonItem(result, item); !ok {
			return base.CommandCliError
		}
	}

	return base.CommandSuccess
}

var (
	extraOidcActionsFlagsMapFunc = func() map[string][]string { return nil }
	extraOidcSynopsisFunc        = func(*OidcCommand) string { return "" }
	extraOidcFlagsFunc           = func(*OidcCommand, *base.FlagSets, *base.FlagSet) {}
	extraOidcFlagsHandlingFunc   = func(*OidcCommand, *[]authmethods.Option) bool { return true }
	executeExtraOidcActions      = func(_ *OidcCommand, inResult api.GenericResult, inErr error, _ *authmethods.Client, _ uint32, _ []authmethods.Option) (api.GenericResult, error) {
		return inResult, inErr
	}
	printCustomOidcActionOutput = func(*OidcCommand) (bool, error) { return false, nil }
)
