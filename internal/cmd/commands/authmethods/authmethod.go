package authmethods

import (
	"fmt"
	"net/http"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/common"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/sdk/strutil"
	"github.com/kr/pretty"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var _ cli.Command = (*Command)(nil)
var _ cli.CommandAutocomplete = (*Command)(nil)

type Command struct {
	*base.Command

	Func string
}

func (c *Command) Synopsis() string {
	switch c.Func {
	case "create":
		return "Create auth-method resources within Boundary"
	case "update":
		return "Update auth-method resources within Boundary"
	default:
		return common.SynopsisFunc(c.Func, "auth-method")
	}
}

var flagsMap = map[string][]string{
	"read":   {"id"},
	"delete": {"id"},
	"list":   {"scope-id"},
}

func (c *Command) Help() string {
	helpMap := common.HelpMap("auth-method")
	var helpStr string
	switch c.Func {
	case "":
		return base.WrapForHelpText([]string{
			"Usage: boundary auth-methods [sub command] [options] [args]",
			"",
			"  This command allows operations on Boundary auth-method resources. Example:",
			"",
			"    Read an auth-method:",
			"",
			`      $ boundary auth-methods read -id ampw_1234567890`,
			"",
			"  Please see the auth-methods subcommand help for detailed usage information.",
		})
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary auth-methods create [type] [sub command] [options] [args]",
			"",
			"  This command allows create operations on Boundary auth-method resources. Example:",
			"",
			"    Create a password-type auth-method:",
			"",
			`      $ boundary auth-methods create password -name prodops -description "For ProdOps usage"`,
			"",
			"  Please see the typed subcommand help for detailed usage information.",
		})
	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary auth-methods update [type] [sub command] [options] [args]",
			"",
			"  This command allows update operations on Boundary auth-method resources. Example:",
			"",
			"    Update a password-type auth-method:",
			"",
			`      $ boundary auth-methods update password -id ampw_1234567890 -name devops -description "For DevOps usage"`,
			"",
			"  Please see the typed subcommand help for detailed usage information.",
		})
	default:
		helpStr = helpMap[c.Func]()
	}
	return helpStr + c.Flags().Help()
}

func (c *Command) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)

	if len(flagsMap[c.Func]) > 0 {
		f := set.NewFlagSet("Command Options")
		common.PopulateCommonFlags(c.Command, f, resource.AuthMethod.String(), flagsMap[c.Func])
	}

	return set
}

func (c *Command) AutocompleteArgs() complete.Predictor {
	return complete.PredictAnything
}

func (c *Command) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *Command) Run(args []string) int {
	switch c.Func {
	case "", "create", "update":
		return cli.RunResultHelp
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
	if strutil.StrListContains(flagsMap[c.Func], "scope-id") && c.FlagScopeId == "" {
		c.UI.Error("Scope ID must be passed in via -scope-id")
		return 1
	}

	client, err := c.Client()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error creating API client: %s", err.Error()))
		return 2
	}

	var opts []authmethods.Option

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

	authmethodClient := authmethods.NewClient(client)

	existed := true
	var result api.GenericResult
	var listResult api.GenericListResult
	var apiErr *api.Error

	switch c.Func {
	case "read":
		result, apiErr, err = authmethodClient.Read(c.Context, c.FlagId, opts...)
	case "delete":
		_, apiErr, err = authmethodClient.Delete(c.Context, c.FlagId, opts...)
		if apiErr != nil && apiErr.Status == int32(http.StatusNotFound) {
			existed = false
			apiErr = nil
		}
	case "list":
		listResult, apiErr, err = authmethodClient.List(c.Context, c.FlagScopeId, opts...)
	}

	plural := "auth method"
	if c.Func == "list" {
		plural = "auth methods"
	}
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error trying to %s %s: %s", c.Func, plural, err.Error()))
		return 2
	}
	if apiErr != nil {
		c.UI.Error(fmt.Sprintf("Error from controller when performing %s on %s: %s", c.Func, plural, pretty.Sprint(apiErr)))
		return 1
	}

	switch c.Func {
	case "delete":
		switch base.Format(c.UI) {
		case "json":
			c.UI.Output("null")
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
		listedMethods := listResult.GetItems().([]*authmethods.AuthMethod)
		switch base.Format(c.UI) {
		case "json":
			if len(listedMethods) == 0 {
				c.UI.Output("null")
				return 0
			}
			b, err := base.JsonFormatter{}.Format(listedMethods)
			if err != nil {
				c.UI.Error(fmt.Errorf("Error formatting as JSON: %w", err).Error())
				return 1
			}
			c.UI.Output(string(b))

		case "table":
			if len(listedMethods) == 0 {
				c.UI.Output("No auth methods found")
				return 0
			}
			var output []string
			output = []string{
				"",
				"Auth Method information:",
			}
			for i, m := range listedMethods {
				if i > 0 {
					output = append(output, "")
				}
				if true {
					output = append(output,
						fmt.Sprintf("  ID:             %s", m.Id),
					)
				}
				if m.Description != "" {
					output = append(output,
						fmt.Sprintf("    Description:  %s", m.Description),
					)
				}
				if m.Name != "" {
					output = append(output,
						fmt.Sprintf("    Name:         %s", m.Name),
					)
				}
				if true {
					output = append(output,
						fmt.Sprintf("    Type:         %s", m.Type),
						fmt.Sprintf("    Version:      %d", m.Version),
					)
				}
			}
			c.UI.Output(base.WrapForHelpText(output))
		}
		return 0
	}

	method := result.GetItem().(*authmethods.AuthMethod)
	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(generateAuthMethodTableOutput(method))
	case "json":
		b, err := base.JsonFormatter{}.Format(method)
		if err != nil {
			c.UI.Error(fmt.Errorf("Error formatting as JSON: %w", err).Error())
			return 1
		}
		c.UI.Output(string(b))
	}

	return 0
}
