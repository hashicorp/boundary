package users

import (
	"fmt"
	"net/http"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/users"
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
	return common.SynopsisFunc(c.Func, "user")
}

var flagsMap = map[string][]string{
	"create": {"scope-id", "name", "description"},
	"update": {"id", "name", "description", "version"},
	"read":   {"id"},
	"delete": {"id"},
	"list":   {"scope-id"},
}

func (c *Command) Help() string {
	helpMap := common.HelpMap("user")
	if c.Func == "" {
		return helpMap["base"]()
	}
	return helpMap[c.Func]() + c.Flags().Help()
}

func (c *Command) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)

	if len(flagsMap[c.Func]) > 0 {
		f := set.NewFlagSet("Command Options")
		common.PopulateCommonFlags(c.Command, f, resource.User.String(), flagsMap[c.Func])
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

	var opts []users.Option

	switch c.FlagName {
	case "":
	case "null":
		opts = append(opts, users.DefaultName())
	default:
		opts = append(opts, users.WithName(c.FlagName))
	}

	switch c.FlagDescription {
	case "":
	case "null":
		opts = append(opts, users.DefaultDescription())
	default:
		opts = append(opts, users.WithDescription(c.FlagDescription))
	}

	userClient := users.NewClient(client)

	// Perform check-and-set when needed
	var version uint32
	switch c.Func {
	case "create", "read", "delete", "list":
		// These don't udpate so don't need the existing version
	default:
		switch c.FlagVersion {
		case 0:
			opts = append(opts, users.WithAutomaticVersioning(true))
		default:
			version = uint32(c.FlagVersion)
		}
	}

	existed := true
	var result api.GenericResult
	var listResult api.GenericListResult
	var apiErr *api.Error

	switch c.Func {
	case "create":
		result, apiErr, err = userClient.Create(c.Context, c.FlagScopeId, opts...)
	case "update":
		result, apiErr, err = userClient.Update(c.Context, c.FlagId, version, opts...)
	case "read":
		result, apiErr, err = userClient.Read(c.Context, c.FlagId, opts...)
	case "delete":
		_, apiErr, err = userClient.Delete(c.Context, c.FlagId, opts...)
		if apiErr != nil && apiErr.Status == int32(http.StatusNotFound) {
			existed = false
			apiErr = nil
		}
	case "list":
		listResult, apiErr, err = userClient.List(c.Context, c.FlagScopeId, opts...)
	}

	plural := "user"
	if c.Func == "list" {
		plural = "users"
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
		listedUsers := listResult.GetItems().([]*users.User)
		switch base.Format(c.UI) {
		case "json":
			if len(listedUsers) == 0 {
				c.UI.Output("null")
				return 0
			}
			b, err := base.JsonFormatter{}.Format(listedUsers)
			if err != nil {
				c.UI.Error(fmt.Errorf("Error formatting as JSON: %w", err).Error())
				return 1
			}
			c.UI.Output(string(b))

		case "table":
			if len(listedUsers) == 0 {
				c.UI.Output("No users found")
				return 0
			}
			var output []string
			output = []string{
				"",
				"User information:",
			}
			for i, u := range listedUsers {
				if i > 0 {
					output = append(output, "")
				}
				if true {
					output = append(output,
						fmt.Sprintf("  ID:             %s", u.Id),
						fmt.Sprintf("    Version:      %d", u.Version),
					)
				}
				if u.Name != "" {
					output = append(output,
						fmt.Sprintf("    Name:         %s", u.Name),
					)
				}
				if u.Description != "" {
					output = append(output,
						fmt.Sprintf("    Description:  %s", u.Description),
					)
				}
			}
			c.UI.Output(base.WrapForHelpText(output))
		}
		return 0
	}

	user := result.GetItem().(*users.User)
	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(generateUserTableOutput(user))
	case "json":
		b, err := base.JsonFormatter{}.Format(user)
		if err != nil {
			c.UI.Error(fmt.Errorf("Error formatting as JSON: %w", err).Error())
			return 1
		}
		c.UI.Output(string(b))
	}

	return 0
}
