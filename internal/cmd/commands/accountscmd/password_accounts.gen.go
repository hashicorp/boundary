package accountscmd

import (
	"fmt"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/accounts"
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

	return common.SynopsisFunc(c.Func, "account")
}

func (c *PasswordCommand) Help() string {
	var helpStr string
	helpMap := common.HelpMap("account")

	switch c.Func {
	default:

		helpStr = c.extraPasswordHelpFunc(helpMap)
	}

	// Keep linter from complaining if we don't actually generate code using it
	_ = helpMap
	return helpStr
}

var flagsPasswordMap = map[string][]string{

	"create": {"auth-method-id", "name", "description"},

	"update": {"id", "name", "description", "version"},
}

func (c *PasswordCommand) Flags() *base.FlagSets {
	if len(flagsPasswordMap[c.Func]) == 0 {
		return c.FlagSet(base.FlagSetNone)
	}

	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)
	f := set.NewFlagSet("Command Options")
	common.PopulateCommonFlags(c.Command, f, "password-type account", flagsPasswordMap[c.Func])

	extraPasswordFlagsFunc(c, set, f)

	return set
}

func (c *PasswordCommand) Run(args []string) int {
	switch c.Func {
	case "":
		return cli.RunResultHelp
	}

	c.plural = "password-type account"
	switch c.Func {
	case "list":
		c.plural = "password-type accounts"
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

	var opts []accounts.Option

	if strutil.StrListContains(flagsPasswordMap[c.Func], "auth-method-id") {
		switch c.Func {
		case "create":
			if c.FlagAuthMethodId == "" {
				c.UI.Error("AuthMethod ID must be passed in via -auth-method-id or BOUNDARY_AUTH_METHOD_ID")
				return 1
			}
		}
	}

	client, err := c.Client()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error creating API client: %s", err.Error()))
		return 2
	}
	accountsClient := accounts.NewClient(client)

	switch c.FlagName {
	case "":
	case "null":
		opts = append(opts, accounts.DefaultName())
	default:
		opts = append(opts, accounts.WithName(c.FlagName))
	}

	switch c.FlagDescription {
	case "":
	case "null":
		opts = append(opts, accounts.DefaultDescription())
	default:
		opts = append(opts, accounts.WithDescription(c.FlagDescription))
	}

	var version uint32

	switch c.Func {
	case "update":
		switch c.FlagVersion {
		case 0:
			opts = append(opts, accounts.WithAutomaticVersioning(true))
		default:
			version = uint32(c.FlagVersion)
		}
	}

	if ret := extraPasswordFlagsHandlingFunc(c, &opts); ret != 0 {
		return ret
	}

	c.existed = true
	var result api.GenericResult

	switch c.Func {

	case "create":
		result, err = accountsClient.Create(c.Context, c.FlagAuthMethodId, opts...)

	case "update":
		result, err = accountsClient.Update(c.Context, c.FlagId, version, opts...)

	}

	result, err = executeExtraPasswordActions(c, result, err, accountsClient, version, opts)

	if err != nil {
		if apiErr := api.AsServerError(err); apiErr != nil {
			c.UI.Error(fmt.Sprintf("Error from controller when performing %s on %s: %s", c.Func, c.plural, base.PrintApiError(apiErr)))
			return 1
		}
		c.UI.Error(fmt.Sprintf("Error trying to %s %s: %s", c.Func, c.plural, err.Error()))
		return 2
	}

	output, err := printCustomPasswordActionOutput(c)
	if err != nil {
		c.UI.Error(err.Error())
		return 1
	}
	if output {
		return 0
	}

	switch c.Func {
	}

	item := result.GetItem().(*accounts.Account)
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
	extraPasswordFlagsFunc         = func(*PasswordCommand, *base.FlagSets, *base.FlagSet) {}
	extraPasswordFlagsHandlingFunc = func(*PasswordCommand, *[]accounts.Option) int { return 0 }
	executeExtraPasswordActions    = func(_ *PasswordCommand, inResult api.GenericResult, inErr error, _ *accounts.Client, _ uint32, _ []accounts.Option) (api.GenericResult, error) {
		return inResult, inErr
	}
	printCustomPasswordActionOutput = func(*PasswordCommand) (bool, error) { return false, nil }
)
