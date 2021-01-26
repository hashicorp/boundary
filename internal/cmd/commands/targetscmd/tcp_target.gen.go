package targetscmd

import (
	"fmt"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/common"
	"github.com/hashicorp/boundary/sdk/strutil"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

func init() {
	for k, v := range extraTcpActionsFlagsMap {
		flagsTcpMap[k] = append(flagsTcpMap[k], v...)
	}
}

var (
	_ cli.Command             = (*TcpCommand)(nil)
	_ cli.CommandAutocomplete = (*TcpCommand)(nil)
)

type TcpCommand struct {
	*base.Command

	Func string

	// Used for delete operations
	existed bool
	// Used in some output
	plural string

	extraTcpCmdVars
}

func (c *TcpCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictAnything
}

func (c *TcpCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *TcpCommand) Synopsis() string {
	if extra := c.extraTcpSynopsisFunc(); extra != "" {
		return extra
	}

	return common.SynopsisFunc(c.Func, "target")
}

func (c *TcpCommand) Help() string {
	var helpStr string
	helpMap := common.HelpMap("target")

	switch c.Func {
	default:
		helpStr = c.extraTcpHelpFunc(helpMap)
	}

	// Keep linter from complaining if we don't actually generate code using it
	_ = helpMap
	return helpStr
}

var flagsTcpMap = map[string][]string{

	"create": {"scope-id", "name", "description"},

	"update": {"id", "name", "description", "version"},
}

func (c *TcpCommand) Flags() *base.FlagSets {
	if len(flagsTcpMap[c.Func]) == 0 {
		return c.FlagSet(base.FlagSetNone)
	}

	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)
	f := set.NewFlagSet("Command Options")
	common.PopulateCommonFlags(c.Command, f, "tcp-type target", flagsTcpMap[c.Func])

	c.extraTcpFlagsFunc(f)

	return set
}

func (c *TcpCommand) Run(args []string) int {
	switch c.Func {
	case "":
		return cli.RunResultHelp
	}

	c.plural = "tcp-type target"
	switch c.Func {
	case "list":
		c.plural = "targets"
	}

	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	if strutil.StrListContains(flagsTcpMap[c.Func], "id") && c.FlagId == "" {
		c.UI.Error("ID is required but not passed in via -id")
		return 1
	}

	var opts []targets.Option

	if strutil.StrListContains(flagsTcpMap[c.Func], "scope-id") {
		switch c.Func {
		default:
			if c.FlagScopeId != "" {
				opts = append(opts, targets.WithScopeId(c.FlagScopeId))
			}
		}
	}

	client, err := c.Client()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error creating API client: %s", err.Error()))
		return 2
	}
	targetClient := targets.NewClient(client)

	switch c.FlagName {
	case "":
	case "null":
		opts = append(opts, targets.DefaultName())
	default:
		opts = append(opts, targets.WithName(c.FlagName))
	}

	switch c.FlagDescription {
	case "":
	case "null":
		opts = append(opts, targets.DefaultDescription())
	default:
		opts = append(opts, targets.WithDescription(c.FlagDescription))
	}

	switch c.FlagRecursive {
	case true:
		opts = append(opts, targets.WithRecursive(true))
	}

	var version uint32
	switch c.Func {
	case "update":
		switch c.FlagVersion {
		case 0:
			opts = append(opts, targets.WithAutomaticVersioning(true))
		default:
			version = uint32(c.FlagVersion)
		}
	}

	if ret := c.extraTcpFlagHandlingFunc(&opts); ret != 0 {
		return ret
	}

	c.existed = true
	var result api.GenericResult

	switch c.Func {

	case "create":
		result, err = targetClient.Create(c.Context, "tcp", c.FlagScopeId, opts...)

	case "update":
		result, err = targetClient.Update(c.Context, c.FlagId, version, opts...)

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

	item := result.GetItem().(*targets.Target)
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
