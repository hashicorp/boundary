package roles

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/helper/strutil"
	"github.com/hashicorp/watchtower/api"
	"github.com/hashicorp/watchtower/api/roles"
	"github.com/hashicorp/watchtower/api/scopes"
	"github.com/hashicorp/watchtower/internal/cmd/base"
	"github.com/hashicorp/watchtower/internal/perms"
	"github.com/kr/pretty"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var _ cli.Command = (*Command)(nil)
var _ cli.CommandAutocomplete = (*Command)(nil)

type Command struct {
	*base.Command

	Func string

	flagId           string
	flagName         string
	flagDescription  string
	flagGrantScopeId string
	flagPrincipals   []string
	flagGrants       []string
}

func (c *Command) Synopsis() string {
	switch c.Func {
	case "create", "update", "read", "delete", "list":
		return synopsisFunc(c.Func)
	case "add-principals", "set-principals", "remove-principals":
		return principalsGrantsSynopsisFunc(c.Func, true)
	case "add-grants", "set-grants", "remove-grants":
		return principalsGrantsSynopsisFunc(c.Func, false)
	}
	return "Manage Watchtower roles"
}

var helpMap = map[string]func() string{
	"create":            createHelp,
	"update":            updateHelp,
	"read":              readHelp,
	"delete":            deleteHelp,
	"list":              listHelp,
	"add-principals":    addPrincipalsHelp,
	"set-principals":    setPrincipalsHelp,
	"remove-principals": removePrincipalsHelp,
	"add-grants":        addPrincipalsHelp,
	"set-grants":        setPrincipalsHelp,
	"remove-grants":     removePrincipalsHelp,
}

var flagsMap = map[string][]string{
	"create":            {"name", "description", "grantscopeid"},
	"update":            {"id", "name", "description", "grantscopeid"},
	"read":              {"id"},
	"delete":            {"id"},
	"add-principals":    {"id", "principal"},
	"set-principals":    {"id", "principal"},
	"remove-principals": {"id", "principal"},
	"add-grants":        {"id", "grant"},
	"set-grants":        {"id", "grant"},
	"remove-grants":     {"id", "grant"},
}

func (c *Command) Help() string {
	if c.Func == "" {
		return baseHelp()
	}
	return helpMap[c.Func]() + "\n\n" + c.Flags().Help()
}

func (c *Command) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)

	f := set.NewFlagSet("Command Options")

	populateFlags(c, f, flagsMap[c.Func])
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

	if strutil.StrListContains(flagsMap[c.Func], "id") && c.flagId == "" {
		c.UI.Error("ID is required but not passed in via -id")
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

	principals := c.flagPrincipals
	grants := c.flagGrants
	switch c.Func {
	case "add-principals", "remove-principals":
		if len(c.flagPrincipals) == 0 {
			c.UI.Error("No principals supplied via -principal")
			return 1
		}

	case "add-grants", "remove-grants":
		if len(c.flagGrants) == 0 {
			c.UI.Error("No grants supplied via -grant")
			return 1
		}

	case "set-principals":
		switch len(c.flagPrincipals) {
		case 0:
		case 1:
			if c.flagPrincipals[0] == "null" {
				principals = []string{}
			}
		}
		if principals == nil {
			c.UI.Error("No principals supplied via -principals")
			return 1
		}

	case "set-grants":
		switch len(c.flagGrants) {
		case 0:
		case 1:
			if c.flagGrants[0] == "null" {
				grants = []string{}
			}
		}
		if grants == nil {
			c.UI.Error("No grants supplied via -grant")
			return 1
		}
	}

	if len(grants) > 0 {
		for _, grant := range grants {
			_, err := perms.Parse("global", "", grant)
			if err != nil {
				c.UI.Error(fmt.Errorf("Grant %q could not be parsed successfully: %w", grant, err).Error())
				return 1
			}
		}
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

	// Perform check-and-set when needed
	switch c.Func {
	case "create", "read", "delete", "list":
		// These don't udpate so don't need the existing version
	default:
		existingRole, existingApiErr, existingErr := actor.ReadRole(c.Context, role)
		if existingErr != nil {
			c.UI.Error(fmt.Sprintf("Error performing initial check-and-set read: %s", err.Error()))
			return 2
		}
		if existingApiErr != nil {
			c.UI.Error(fmt.Sprintf("Error from controller when performing initial check-and-set read: %s", pretty.Sprint(apiErr)))
			return 1
		}
		role.Version = existingRole.Version
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
	case "add-principals":
		role, apiErr, err = role.AddPrincipals(c.Context, principals)
	case "set-principals":
		role, apiErr, err = role.SetPrincipals(c.Context, principals)
	case "remove-principals":
		role, apiErr, err = role.RemovePrincipals(c.Context, principals)
	case "add-grants":
		role, apiErr, err = role.AddGrants(c.Context, grants)
	case "set-grants":
		role, apiErr, err = role.SetGrants(c.Context, grants)
	case "remove-grants":
		role, apiErr, err = role.RemoveGrants(c.Context, grants)
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
		if len(listedRoles) == 0 {
			c.UI.Output("No roles found")
			return 0
		}
		switch base.Format(c.UI) {
		case "json":
			b, err := base.JsonFormatter{}.Format(listedRoles)
			if err != nil {
				c.UI.Error(fmt.Errorf("Error formatting to JSON: %w", err).Error())
				return 1
			}
			c.UI.Output(string(b))
		case "table":
			var output []string
			output = []string{
				"",
				"Role information:",
			}
			for i, r := range listedRoles {
				if i > 0 {
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
		}
		return 0
	}

	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(generateRoleTableOutput(role))
	case "json":
		b, err := base.JsonFormatter{}.Format(role)
		if err != nil {
			c.UI.Error(fmt.Errorf("Error formatting to JSON: %w", err).Error())
			return 1
		}
		c.UI.Output(string(b))
	}

	return 0
}
