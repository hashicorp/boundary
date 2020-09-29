package scopes

import (
	"fmt"
	"net/http"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/common"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/sdk/strutil"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var _ cli.Command = (*Command)(nil)
var _ cli.CommandAutocomplete = (*Command)(nil)

type Command struct {
	*base.Command

	Func string

	flagSkipAdminRoleCreation   bool
	flagSkipDefaultRoleCreation bool
}

func (c *Command) Synopsis() string {
	return common.SynopsisFunc(c.Func, "scope")
}

var flagsMap = map[string][]string{
	"create": {"scope-id", "name", "description", "skip-admin-role-creation", "skip-default-role-creation"},
	"update": {"id", "name", "description", "version"},
	"read":   {"id"},
	"delete": {"id"},
	"list":   {"scope-id"},
}

func (c *Command) Help() string {
	helpMap := common.HelpMap("scope")
	if c.Func == "" {
		return helpMap["base"]()
	}
	return helpMap[c.Func]() + c.Flags().Help()
}

func (c *Command) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)

	if len(flagsMap[c.Func]) > 0 {
		f := set.NewFlagSet("Command Options")
		common.PopulateCommonFlags(c.Command, f, resource.Scope.String(), flagsMap[c.Func])
		if c.Func == "create" {
			f.BoolVar(&base.BoolVar{
				Name:   "skip-admin-role-creation",
				Target: &c.flagSkipAdminRoleCreation,
				Usage:  "If set, a role granting the current user access to administer the newly-created scope will not automatically be created",
			})
			f.BoolVar(&base.BoolVar{
				Name:   "skip-default-role-creation",
				Target: &c.flagSkipDefaultRoleCreation,
				Usage:  "If set, a role granting the anonymous user access to log into auth methods and a few other actions within the newly-created scope will not automatically be created",
			})
		}
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

	var opts []scopes.Option

	switch c.FlagName {
	case "":
	case "null":
		opts = append(opts, scopes.DefaultName())
	default:
		opts = append(opts, scopes.WithName(c.FlagName))
	}

	switch c.FlagDescription {
	case "":
	case "null":
		opts = append(opts, scopes.DefaultDescription())
	default:
		opts = append(opts, scopes.WithDescription(c.FlagDescription))
	}

	if c.flagSkipAdminRoleCreation {
		opts = append(opts, scopes.WithSkipAdminRoleCreation(c.flagSkipAdminRoleCreation))
	}
	if c.flagSkipDefaultRoleCreation {
		opts = append(opts, scopes.WithSkipDefaultRoleCreation(c.flagSkipDefaultRoleCreation))
	}

	scopeClient := scopes.NewClient(client)

	// Perform check-and-set when needed
	var version uint32
	switch c.Func {
	case "create", "read", "delete", "list":
		// These don't udpate so don't need the existing version
	default:
		switch c.FlagVersion {
		case 0:
			opts = append(opts, scopes.WithAutomaticVersioning(true))
		default:
			version = uint32(c.FlagVersion)
		}
	}

	existed := true
	var result api.GenericResult
	var listResult api.GenericListResult

	switch c.Func {
	case "create":
		result, err = scopeClient.Create(c.Context, c.FlagScopeId, opts...)
	case "update":
		result, err = scopeClient.Update(c.Context, c.FlagId, version, opts...)
	case "read":
		result, err = scopeClient.Read(c.Context, c.FlagId, opts...)
	case "delete":
		_, err = scopeClient.Delete(c.Context, c.FlagId, opts...)
		if apiErr := api.AsServerError(err); apiErr != nil && apiErr.Status == int32(http.StatusNotFound) {
			existed = false
			err = nil
		}
	case "list":
		listResult, err = scopeClient.List(c.Context, c.FlagScopeId, opts...)
	}

	plural := "scope"
	if c.Func == "list" {
		plural = "scopes"
	}
	if err != nil {
		if api.AsServerError(err) != nil {
			c.UI.Error(fmt.Sprintf("Error from controller when performing %s on %s: %s", c.Func, plural, err.Error()))
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
		listedScopes := listResult.GetItems().([]*scopes.Scope)
		switch base.Format(c.UI) {
		case "json":
			if len(listedScopes) == 0 {
				c.UI.Output("null")
				return 0
			}
			b, err := base.JsonFormatter{}.Format(listedScopes)
			if err != nil {
				c.UI.Error(fmt.Errorf("Error formatting as JSON: %w", err).Error())
				return 1
			}
			c.UI.Output(string(b))

		case "table":
			if len(listedScopes) == 0 {
				c.UI.Output("No child scopes found")
				return 0
			}
			var output []string
			output = []string{
				"",
				"Scope information:",
			}
			for i, s := range listedScopes {
				if i > 0 {
					output = append(output, "")
				}
				if true {
					output = append(output,
						fmt.Sprintf("  ID:             %s", s.Id),
						fmt.Sprintf("    Version:      %d", s.Version),
					)
				}
				if s.Name != "" {
					output = append(output,
						fmt.Sprintf("    Name:         %s", s.Name),
					)
				}
				if s.Description != "" {
					output = append(output,
						fmt.Sprintf("    Description:  %s", s.Description),
					)
				}
			}
			c.UI.Output(base.WrapForHelpText(output))
		}
		return 0
	}

	scope := result.GetItem().(*scopes.Scope)
	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(generateScopeTableOutput(scope))
	case "json":
		b, err := base.JsonFormatter{}.Format(scope)
		if err != nil {
			c.UI.Error(fmt.Errorf("Error formatting as JSON: %w", err).Error())
			return 1
		}
		c.UI.Output(string(b))
	}

	return 0
}
