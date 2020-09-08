package targets

import (
	"fmt"
	"net/textproto"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/common"
	"github.com/hashicorp/vault/sdk/helper/strutil"
	"github.com/kr/pretty"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var _ cli.Command = (*TcpCommand)(nil)
var _ cli.CommandAutocomplete = (*TcpCommand)(nil)

type TcpCommand struct {
	*base.Command

	Func string
}

func (c *TcpCommand) Synopsis() string {
	return fmt.Sprintf("%s a tcp-type target within Boundary", textproto.CanonicalMIMEHeaderKey(c.Func))
}

var tcpFlagsMap = map[string][]string{
	"create": {"scope-id", "name", "description"},
	"update": {"id", "name", "description", "version"},
}

func (c *TcpCommand) Help() string {
	var info string
	switch c.Func {
	case "create":
		info = base.WrapForHelpText([]string{
			"Usage: boundary targets tcp create [options] [args]",
			"",
			"  Create a tcp-type target. Example:",
			"",
			`    $ boundary targets tcp create -name prodops -description "Tcp target for ProdOps"`,
			"",
			"",
		})

	case "update":
		info = base.WrapForHelpText([]string{
			"Usage: boundary targets tcp update [options] [args]",
			"",
			"  Update a tcp-type target given its ID. Example:",
			"",
			`    $ boundary targets tcp update -id ttcp_1234567890 -name "devops" -description "Tcp target for DevOps"`,
			"",
			"",
		})
	}
	return info + c.Flags().Help()
}

func (c *TcpCommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)

	if len(tcpFlagsMap[c.Func]) > 0 {
		f := set.NewFlagSet("Command Options")
		common.PopulateCommonFlags(c.Command, f, "tcp-type target", tcpFlagsMap[c.Func])
	}

	return set
}

func (c *TcpCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictAnything
}

func (c *TcpCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *TcpCommand) Run(args []string) int {
	if c.Func == "" {
		return cli.RunResultHelp
	}

	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	if strutil.StrListContains(tcpFlagsMap[c.Func], "id") && c.FlagId == "" {
		c.UI.Error("ID is required but not passed in via -id")
		return 1
	}
	if strutil.StrListContains(tcpFlagsMap[c.Func], "scope-id") && c.FlagScopeId == "" {
		c.UI.Error("Scope ID must be passed in via -scope-id")
		return 1
	}

	client, err := c.Client()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error creating API client: %s", err.Error()))
		return 2
	}

	var opts []targets.Option

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

	targetClient := targets.NewClient(client)

	// Perform check-and-set when needed
	var version uint32
	switch c.Func {
	case "create":
		// These don't update so don't need the existing version
	default:
		switch c.FlagVersion {
		case 0:
			opts = append(opts, targets.WithAutomaticVersioning(true))
		default:
			version = uint32(c.FlagVersion)
		}
	}

	var catalog *targets.Target
	var apiErr *api.Error

	switch c.Func {
	case "create":
		catalog, apiErr, err = targetClient.Create(c.Context, "tcp", c.FlagScopeId, opts...)
	case "update":
		catalog, apiErr, err = targetClient.Update(c.Context, c.FlagId, version, opts...)
	}

	plural := "tcp-type target"
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error trying to %s %s: %s", c.Func, plural, err.Error()))
		return 2
	}
	if apiErr != nil {
		c.UI.Error(fmt.Sprintf("Error from controller when performing %s on %s: %s", c.Func, plural, pretty.Sprint(apiErr)))
		return 1
	}

	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(generateTargetTableOutput(catalog))
	case "json":
		b, err := base.JsonFormatter{}.Format(catalog)
		if err != nil {
			c.UI.Error(fmt.Errorf("Error formatting as JSON: %w", err).Error())
			return 1
		}
		c.UI.Output(string(b))
	}

	return 0
}
