package authmethodscmd

import (
	"fmt"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/common"
	"github.com/hashicorp/boundary/sdk/strutil"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

func init() {
	for k, v := range extraPasswordActionsFlagsMap {
		flagsPasswordMap[k] = append(flagsPasswordMap[k], v...)
	}
}

var (
	_ cli.Command             = (*PasswordCommand)(nil)
	_ cli.CommandAutocomplete = (*PasswordCommand)(nil)
)

type PasswordCommand struct {
	*base.Command

	Func string

	// Used for delete operations
	existed bool
	// Used in some output
	plural string

	extraPasswordCmdVars
}

func (c *PasswordCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictAnything
}

func (c *PasswordCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *PasswordCommand) Synopsis() string {
	if extra := c.extraPasswordSynopsisFunc(); extra != "" {
		return extra
	}

	return common.SynopsisFunc(c.Func, "auth method")
}

func (c *PasswordCommand) Help() string {
	var helpStr string
	helpMap := common.HelpMap("auth method")

	switch c.Func {
	default:
		helpStr = c.extraPasswordHelpFunc(helpMap)
	}

	// Keep linter from complaining if we don't actually generate code using it
	_ = helpMap
	return helpStr
}

var flagsPasswordMap = map[string][]string{

	"create": {"scope-id", "name", "description"},

	"update": {"id", "name", "description", "version"},
}

func (c *PasswordCommand) Flags() *base.FlagSets {
	if len(flagsPasswordMap[c.Func]) == 0 {
		return c.FlagSet(base.FlagSetNone)
	}

	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)
	f := set.NewFlagSet("Command Options")
	common.PopulateCommonFlags(c.Command, f, "password-type auth method", flagsPasswordMap[c.Func])

	c.extraPasswordFlagsFunc(set, f)

	return set
}

func (c *PasswordCommand) Run(args []string) int {
	switch c.Func {
	case "":
		return cli.RunResultHelp
	}

	c.plural = "password-type auth method"
	switch c.Func {
	case "list":
		c.plural = "password-type auth methods"
	}

	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	if strutil.StrListContains(flagsPasswordMap[c.Func], "id") && c.FlagId == "" {
		c.UI.Error("ID is required but not passed in via -id")
		return 1
	}

	var opts []authmethods.Option

	if strutil.StrListContains(flagsPasswordMap[c.Func], "scope-id") {
		switch c.Func {
		case "create":
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

	var version uint32
	switch c.Func {
	case "update":
		switch c.FlagVersion {
		case 0:
			opts = append(opts, authmethods.WithAutomaticVersioning(true))
		default:
			version = uint32(c.FlagVersion)
		}
	}

	if ret := c.extraPasswordFlagHandlingFunc(&opts); ret != 0 {
		return ret
	}

	c.existed = true
	var result api.GenericResult

	switch c.Func {

	case "create":
		result, err = authmethodsClient.Create(c.Context, "password", c.FlagScopeId, opts...)

	case "update":
		result, err = authmethodsClient.Update(c.Context, c.FlagId, version, opts...)

	}

	if err != nil {
		if apiErr := api.AsServerError(err); apiErr != nil {
			c.UI.Error(fmt.Sprintf("Error from controller when performing %s on %s: %s", c.Func, c.plural, base.PrintApiError(apiErr)))
			return 1
		}
		c.UI.Error(fmt.Sprintf("Error trying to %s %s: %s", c.Func, c.plural, err.Error()))
		return 2
	}

	switch c.Func {
	}

	item := result.GetItem().(*authmethods.AuthMethod)
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
