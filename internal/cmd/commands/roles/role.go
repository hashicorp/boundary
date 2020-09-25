package roles

import (
	"fmt"
	"net/http"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/roles"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/common"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/sdk/strutil"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var _ cli.Command = (*Command)(nil)
var _ cli.CommandAutocomplete = (*Command)(nil)

type Command struct {
	*base.Command

	Func string

	flagScope        string
	flagGrantScopeId string
	flagPrincipals   []string
	flagGrants       []string
}

func (c *Command) Synopsis() string {
	switch c.Func {
	case "", "create", "update", "read", "delete", "list":
		return common.SynopsisFunc(c.Func, "role")
	case "add-principals", "set-principals", "remove-principals":
		return principalsGrantsSynopsisFunc(c.Func, true)
	case "add-grants", "set-grants", "remove-grants":
		return principalsGrantsSynopsisFunc(c.Func, false)
	}
	return ""
}

var helpMap = func() map[string]func() string {
	ret := common.HelpMap("role")
	ret["add-principals"] = addPrincipalsHelp
	ret["set-principals"] = setPrincipalsHelp
	ret["remove-principals"] = removePrincipalsHelp
	ret["add-grants"] = addPrincipalsHelp
	ret["set-grants"] = setPrincipalsHelp
	ret["remove-grants"] = removePrincipalsHelp
	return ret
}

var flagsMap = map[string][]string{
	"create":            {"scope-id", "name", "description", "grantscopeid"},
	"update":            {"id", "name", "description", "grantscopeid", "version"},
	"read":              {"id"},
	"delete":            {"id"},
	"list":              {"scope-id"},
	"add-principals":    {"id", "principal", "version"},
	"set-principals":    {"id", "principal", "version"},
	"remove-principals": {"id", "principal", "version"},
	"add-grants":        {"id", "grant", "version"},
	"set-grants":        {"id", "grant", "version"},
	"remove-grants":     {"id", "grant", "version"},
}

func (c *Command) Help() string {
	hm := helpMap()
	if c.Func == "" {
		return hm["base"]()
	}
	return hm[c.Func]() + c.Flags().Help()
}

func (c *Command) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)

	if len(flagsMap[c.Func]) > 0 {
		f := set.NewFlagSet("Command Options")
		populateFlags(c, f, flagsMap[c.Func])
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

	var opts []roles.Option

	switch c.FlagName {
	case "":
	case "null":
		opts = append(opts, roles.DefaultName())
	default:
		opts = append(opts, roles.WithName(c.FlagName))
	}
	switch c.FlagDescription {
	case "":
	case "null":
		opts = append(opts, roles.DefaultDescription())
	default:
		opts = append(opts, roles.WithDescription(c.FlagDescription))
	}
	switch c.flagGrantScopeId {
	case "":
	case "null":
		opts = append(opts, roles.DefaultGrantScopeId())
	default:
		opts = append(opts, roles.WithGrantScopeId(c.flagGrantScopeId))
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
			c.UI.Error("No principals supplied via -principal")
			return 1
		case 1:
			if c.flagPrincipals[0] == "null" {
				principals = nil
			}
		}

	case "set-grants":
		switch len(c.flagGrants) {
		case 0:
			c.UI.Error("No grants supplied via -grant")
			return 1
		case 1:
			if c.flagGrants[0] == "null" {
				grants = nil
			}
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

	roleClient := roles.NewClient(client)

	// Perform check-and-set when needed
	var version uint32
	switch c.Func {
	case "create", "read", "delete", "list":
		// These don't udpate so don't need the existing version
	default:
		switch c.FlagVersion {
		case 0:
			opts = append(opts, roles.WithAutomaticVersioning(true))
		default:
			version = uint32(c.FlagVersion)
		}
	}

	existed := true
	var result api.GenericResult
	var listResult api.GenericListResult

	switch c.Func {
	case "create":
		result, err = roleClient.Create(c.Context, c.FlagScopeId, opts...)
	case "update":
		result, err = roleClient.Update(c.Context, c.FlagId, version, opts...)
	case "read":
		result, err = roleClient.Read(c.Context, c.FlagId, opts...)
	case "delete":
		_, err = roleClient.Delete(c.Context, c.FlagId, opts...)
		if apiErr := api.AsServerError(err); apiErr != nil && apiErr.Status == int32(http.StatusNotFound) {
			existed = false
			err = nil
		}
	case "list":
		listResult, err = roleClient.List(c.Context, c.FlagScopeId, opts...)
	case "add-principals":
		result, err = roleClient.AddPrincipals(c.Context, c.FlagId, version, principals, opts...)
	case "set-principals":
		result, err = roleClient.SetPrincipals(c.Context, c.FlagId, version, principals, opts...)
	case "remove-principals":
		result, err = roleClient.RemovePrincipals(c.Context, c.FlagId, version, principals, opts...)
	case "add-grants":
		result, err = roleClient.AddGrants(c.Context, c.FlagId, version, grants, opts...)
	case "set-grants":
		result, err = roleClient.SetGrants(c.Context, c.FlagId, version, grants, opts...)
	case "remove-grants":
		result, err = roleClient.RemoveGrants(c.Context, c.FlagId, version, grants, opts...)
	}

	plural := "role"
	if c.Func == "list" {
		plural = "roles"
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
		listedRoles := listResult.GetItems().([]*roles.Role)
		switch base.Format(c.UI) {
		case "json":
			if len(listedRoles) == 0 {
				c.UI.Output("null")
				return 0
			}
			b, err := base.JsonFormatter{}.Format(listedRoles)
			if err != nil {
				c.UI.Error(fmt.Errorf("Error formatting as JSON: %w", err).Error())
				return 1
			}
			c.UI.Output(string(b))

		case "table":
			if len(listedRoles) == 0 {
				c.UI.Output("No roles found")
				return 0
			}
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
						fmt.Sprintf("  ID:            %s", r.Id),
						fmt.Sprintf("    Version:     %d", r.Version),
					)
				}
				if r.Name != "" {
					output = append(output,
						fmt.Sprintf("    Name:        %s", r.Name),
					)
				}
				if r.Description != "" {
					output = append(output,
						fmt.Sprintf("    Description: %s", r.Description),
					)
				}
			}
			c.UI.Output(base.WrapForHelpText(output))
		}
		return 0
	}

	role := result.GetItem().(*roles.Role)
	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(generateRoleTableOutput(role))
	case "json":
		b, err := base.JsonFormatter{}.Format(role)
		if err != nil {
			c.UI.Error(fmt.Errorf("Error formatting as JSON: %w", err).Error())
			return 1
		}
		c.UI.Output(string(b))
	}

	return 0
}
