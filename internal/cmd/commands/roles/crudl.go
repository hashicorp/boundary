package roles

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/watchtower/api"
	"github.com/hashicorp/watchtower/api/roles"
	"github.com/hashicorp/watchtower/api/scopes"
	"github.com/hashicorp/watchtower/internal/cmd/base"
	"github.com/kr/pretty"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var _ cli.Command = (*CRUDLCommand)(nil)
var _ cli.CommandAutocomplete = (*CRUDLCommand)(nil)

type CRUDLCommand struct {
	*base.Command

	Func string

	flagId           string
	flagName         string
	flagDescription  string
	flagGrantScopeId string
}

func (c *CRUDLCommand) Synopsis() string {
	return synopsisFunc(c.Func)
}

var helpMap = map[string]func(string) string{
	"create": createHelp,
	"update": updateHelp,
	"read":   readHelp,
	"delete": deleteHelp,
	"list":   listHelp,
}

func (c *CRUDLCommand) Help() string {
	return helpMap[c.Func](c.Flags().Help())
}

func (c *CRUDLCommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)

	f := set.NewFlagSet("Command Options")

	switch c.Func {
	case "create":
		populateFlags(c, f, []string{"name", "description", "grantscopeid"})
	case "update":
		populateFlags(c, f, []string{"id", "name", "description", "grantscopeid"})
	case "read":
		populateFlags(c, f, []string{"id"})
	case "delete":
		populateFlags(c, f, []string{"id"})
	}

	return set
}

func (c *CRUDLCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictAnything
}

func (c *CRUDLCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *CRUDLCommand) Run(args []string) int {
	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	client, err := c.Client()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error creating API client: %s", err.Error()))
		return 2
	}

	role := &roles.Role{
		Client: client,
		Id:     c.flagId,
	}
	switch c.flagName {
	case "":
	case "null":
		role.SetDefault("name")
	default:
		role.Name = api.String(c.flagName)
	}
	switch c.flagDescription {
	case "":
	case "null":
		role.SetDefault("description")
	default:
		role.Description = api.String(c.flagDescription)
	}
	switch c.flagGrantScopeId {
	case "":
	case "null":
		role.SetDefault("grantscopeid")
	default:
		role.GrantScopeId = api.String(c.flagGrantScopeId)
	}

	var apiErr *api.Error

	type crudl interface {
		CreateRole(context.Context, *roles.Role) (*roles.Role, *api.Error, error)
		UpdateRole(context.Context, *roles.Role) (*roles.Role, *api.Error, error)
		ReadRole(context.Context, *roles.Role) (*roles.Role, *api.Error, error)
		DeleteRole(context.Context, *roles.Role) (bool, *api.Error, error)
		ListRoles(context.Context) ([]*roles.Role, *api.Error, error)
	}
	var actor crudl
	var existed bool
	var listedRoles []*roles.Role

	switch {
	case client.Project() != "":
		project := &scopes.Project{
			Client: client,
		}
		actor = project

	case client.Org() != "":
		org := &scopes.Org{
			Client: client,
		}
		actor = org

	default:
		// TODO: Handle global case
		c.UI.Error("TODO")
	}

	if actor == nil {
		c.UI.Error("Unable to determine the right scope for the command")
		return 1
	}

	switch c.Func {
	case "create":
		role, apiErr, err = actor.CreateRole(c.Context, role)
	case "update":
		role, apiErr, err = actor.UpdateRole(c.Context, role)
	case "read":
		role, apiErr, err = actor.ReadRole(c.Context, role)
	case "delete":
		existed, apiErr, err = actor.DeleteRole(c.Context, role)
	case "list":
		listedRoles, apiErr, err = actor.ListRoles(c.Context)
	}

	plural := "role"
	if c.Func == "list" {
		plural = "roles"
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
		output := "The delete operation completed successfully"
		switch existed {
		case true:
			output += "."
		default:
			output += ", however the resource did not exist at the time."
		}
		c.UI.Output(output)
		return 0

	case "list":
		if len(listedRoles) == 0 {
			c.UI.Output("No roles found")
			return 0
		}
		var output []string
		output = []string{
			"",
			"Role information:",
			"",
		}
		for i, r := range listedRoles {
			if i > 1 {
				output = append(output, "")
			}
			if true {
				output = append(output,
					fmt.Sprintf("  ID:               %s", r.Id),
				)
			}
			if r.Name != nil {
				output = append(output,
					fmt.Sprintf("    Name:           %s", *r.Name),
				)
			}
			if r.Description != nil {
				output = append(output,
					fmt.Sprintf("    Description:    %s", *r.Description),
				)
			}
		}
		c.UI.Output(base.WrapForHelpText(output))
		return 0
	}

	switch base.Format(c.UI) {
	case "table":
		var output []string
		if true {
			output = []string{
				"",
				"Role information:",
				fmt.Sprintf("  ID:             %s", role.Id),
				fmt.Sprintf("  Created At:     %s", role.CreatedTime.Local().Format(time.RFC3339)),
				fmt.Sprintf("  Updated At:     %s", role.UpdatedTime.Local().Format(time.RFC3339)),
				fmt.Sprintf("  Version:        %d", role.Version),
			}
		}
		if role.Name != nil {
			output = append(output,
				fmt.Sprintf("  Name:           %s", *role.Name),
			)
		}
		if role.Description != nil {
			output = append(output,
				fmt.Sprintf("  Description:    %s", *role.Description),
			)
		}
		if role.GrantScopeId != nil {
			output = append(output,
				fmt.Sprintf("  Grant Scope ID: %s", *role.GrantScopeId),
			)
		}
		c.UI.Output(base.WrapForHelpText(output))
	}

	return 0
}
