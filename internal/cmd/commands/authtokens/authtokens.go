package authtokens

import (
	"fmt"
	"net/http"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/common"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/sdk/strutil"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*Command)(nil)
	_ cli.CommandAutocomplete = (*Command)(nil)
)

type Command struct {
	*base.Command

	Func string
}

func (c *Command) Synopsis() string {
	return common.SynopsisFunc(c.Func, "auth token")
}

var flagsMap = map[string][]string{
	"read":   {"id"},
	"delete": {"id"},
	"list":   {"scope-id", "recursive"},
}

func (c *Command) Help() string {
	helpMap := common.HelpMap("auth token")
	if c.Func == "" {
		return helpMap["base"]()
	}
	return helpMap[c.Func]() + c.Flags().Help()
}

func (c *Command) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)

	if len(flagsMap[c.Func]) > 0 {
		f := set.NewFlagSet("Command Options")
		common.PopulateCommonFlags(c.Command, f, resource.AuthToken.String(), flagsMap[c.Func])
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
	if c.Func == "" {
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

	authtokenClient := authtokens.NewClient(client)

	var opts []authtokens.Option

	switch c.FlagRecursive {
	case true:
		opts = append(opts, authtokens.WithRecursive(true))
	}

	existed := true
	var result api.GenericResult
	var listResult api.GenericListResult

	switch c.Func {
	case "read":
		result, err = authtokenClient.Read(c.Context, c.FlagId, opts...)
	case "delete":
		_, err = authtokenClient.Delete(c.Context, c.FlagId, opts...)
		if apiErr := api.AsServerError(err); apiErr != nil && apiErr.ResponseStatus() == http.StatusNotFound {
			existed = false
			err = nil
		}
	case "list":
		listResult, err = authtokenClient.List(c.Context, c.FlagScopeId, opts...)
	}

	plural := "auth token"
	if c.Func == "list" {
		plural = "auth tokens"
	}
	if err != nil {
		if apiErr := api.AsServerError(err); apiErr != nil {
			c.UI.Error(fmt.Sprintf("Error from controller when performing %s on %s: %s", c.Func, plural, base.PrintApiError(apiErr)))
			return 1
		}
		c.UI.Error(fmt.Sprintf("Error trying to %s %s: %s", c.Func, plural, err.Error()))
		return 2
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
		listedTokens := listResult.GetItems().([]*authtokens.AuthToken)
		switch base.Format(c.UI) {
		case "json":
			if len(listedTokens) == 0 {
				c.UI.Output("null")
				return 0
			}
			b, err := base.JsonFormatter{}.Format(listedTokens)
			if err != nil {
				c.UI.Error(fmt.Errorf("Error formatting as JSON: %w", err).Error())
				return 1
			}
			c.UI.Output(string(b))

		case "table":
			if len(listedTokens) == 0 {
				c.UI.Output("No auth tokens found")
				return 0
			}
			var output []string
			output = []string{
				"",
				"Auth Token information:",
			}
			for i, t := range listedTokens {
				if i > 0 {
					output = append(output, "")
				}
				if true {
					output = append(output,
						fmt.Sprintf("  ID:                            %s", t.Id),
					)
				}
				if c.FlagRecursive {
					output = append(output,
						fmt.Sprintf("    Scope ID:                    %s", t.Scope.Id),
					)
				}
				if true {
					output = append(output,
						fmt.Sprintf("    Approximate Last Used Time:  %s", t.ApproximateLastUsedTime.Local().Format(time.RFC1123)),
						fmt.Sprintf("    Auth Method ID:              %s", t.AuthMethodId),
						fmt.Sprintf("    Created Time:                %s", t.CreatedTime.Local().Format(time.RFC1123)),
						fmt.Sprintf("    Expiration Time:             %s", t.ExpirationTime.Local().Format(time.RFC1123)),
						fmt.Sprintf("    Updated Time:                %s", t.UpdatedTime.Local().Format(time.RFC1123)),
						fmt.Sprintf("    User ID:                     %s", t.UserId),
					)
				}
				if len(t.AuthorizedActions) > 0 {
					output = append(output,
						"    Authorized Actions:",
						base.WrapSlice(6, t.AuthorizedActions),
					)
				}
			}
			c.UI.Output(base.WrapForHelpText(output))
		}
		return 0
	}

	token := result.GetItem().(*authtokens.AuthToken)
	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(generateAuthTokenTableOutput(token))
	case "json":
		b, err := base.JsonFormatter{}.Format(token)
		if err != nil {
			c.UI.Error(fmt.Errorf("Error formatting as JSON: %w", err).Error())
			return 1
		}
		c.UI.Output(string(b))
	}

	return 0
}
