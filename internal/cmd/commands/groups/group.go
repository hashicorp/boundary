package groups

import (
	"fmt"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/groups"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/common"
	"github.com/hashicorp/vault/sdk/helper/strutil"
	"github.com/kr/pretty"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var _ cli.Command = (*Command)(nil)
var _ cli.CommandAutocomplete = (*Command)(nil)

type Command struct {
	*base.Command

	Func string

	flagMembers []string
}

func (c *Command) Synopsis() string {
	switch c.Func {
	case "", "create", "update", "read", "delete", "list":
		return common.SynopsisFunc(c.Func, "group")
	case "add-members", "set-members", "remove-members":
		return memberSynopsisFunc(c.Func)
	}
	return ""
}

var helpMap = func() map[string]func() string {
	ret := common.HelpMap("group")
	ret["add-members"] = addMembersHelp
	ret["set-members"] = setMembersHelp
	ret["remove-members"] = removeMembersHelp
	return ret
}

var flagsMap = map[string][]string{
	"create":         {"name", "description"},
	"update":         {"id", "name", "description", "version"},
	"read":           {"id"},
	"delete":         {"id"},
	"add-members":    {"id", "member", "version"},
	"set-members":    {"id", "member", "version"},
	"remove-members": {"id", "member", "version"},
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

	client, err := c.Client()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error creating API client: %s", err.Error()))
		return 2
	}

	var opts []groups.Option

	switch c.FlagName {
	case "":
	case "null":
		opts = append(opts, groups.DefaultName())
	default:
		opts = append(opts, groups.WithName(c.FlagName))
	}
	switch c.FlagDescription {
	case "":
	case "null":
		opts = append(opts, groups.DefaultDescription())
	default:
		opts = append(opts, groups.WithDescription(c.FlagDescription))
	}

	members := c.flagMembers
	switch c.Func {
	case "add-members", "remove-members":
		if len(c.flagMembers) == 0 {
			c.UI.Error("No members supplied via -member")
			return 1
		}

	case "set-members":
		switch len(c.flagMembers) {
		case 0:
		case 1:
			if c.flagMembers[0] == "null" {
				members = []string{}
			}
		}
		if members == nil {
			c.UI.Error("No members supplied via -member")
			return 1
		}
	}

	groupClient := groups.NewGroupsClient(client)

	// Perform check-and-set when needed
	var version uint32
	switch c.Func {
	case "create", "read", "delete", "list":
		// These don't udpate so don't need the existing version
	default:
		switch c.FlagVersion {
		case 0:
			opts = append(opts, groups.WithAutomaticVersioning())
		default:
			version = uint32(c.FlagVersion)
		}
	}

	var existed bool
	var group *groups.Group
	var listedGroups []*groups.Group
	var apiErr *api.Error

	switch c.Func {
	case "create":
		group, apiErr, err = groupClient.Create(c.Context, opts...)
	case "update":
		group, apiErr, err = groupClient.Update(c.Context, c.FlagId, version, opts...)
	case "read":
		group, apiErr, err = groupClient.Read(c.Context, c.FlagId, opts...)
	case "delete":
		existed, apiErr, err = groupClient.Delete(c.Context, c.FlagId, opts...)
	case "list":
		listedGroups, apiErr, err = groupClient.List(c.Context, opts...)
	case "add-members":
		group, apiErr, err = groupClient.AddMembers(c.Context, c.FlagId, version, members, opts...)
	case "set-members":
		group, apiErr, err = groupClient.SetMembers(c.Context, c.FlagId, version, members, opts...)
	case "remove-members":
		group, apiErr, err = groupClient.RemoveMembers(c.Context, c.FlagId, version, members, opts...)
	}

	plural := "group"
	if c.Func == "list" {
		plural = "groups"
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
		switch base.Format(c.UI) {
		case "json":
			if len(listedGroups) == 0 {
				c.UI.Output("null")
				return 0
			}
			b, err := base.JsonFormatter{}.Format(listedGroups)
			if err != nil {
				c.UI.Error(fmt.Errorf("Error formatting as JSON: %w", err).Error())
				return 1
			}
			c.UI.Output(string(b))

		case "table":
			if len(listedGroups) == 0 {
				c.UI.Output("No groups found")
				return 0
			}
			var output []string
			output = []string{
				"",
				"Group information:",
			}
			for i, g := range listedGroups {
				if i > 0 {
					output = append(output, "")
				}
				if true {
					output = append(output,
						fmt.Sprintf("  ID:            %s", g.Id),
						fmt.Sprintf("    Version:     %d", g.Version),
					)
				}
				if g.Name != "" {
					output = append(output,
						fmt.Sprintf("    Name:        %s", g.Name),
					)
				}
				if g.Description != "" {
					output = append(output,
						fmt.Sprintf("    Description: %s", g.Description),
					)
				}
			}
			c.UI.Output(base.WrapForHelpText(output))
		}
		return 0
	}

	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(generateGroupTableOutput(group))
	case "json":
		b, err := base.JsonFormatter{}.Format(group)
		if err != nil {
			c.UI.Error(fmt.Errorf("Error formatting as JSON: %w", err).Error())
			return 1
		}
		c.UI.Output(string(b))
	}

	return 0
}
