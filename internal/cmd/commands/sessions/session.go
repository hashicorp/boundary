package sessions

import (
	"fmt"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/sessions"
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
}

func (c *Command) Synopsis() string {
	return common.SynopsisFunc(c.Func, "session")
}

var flagsMap = map[string][]string{
	"read":   {"id"},
	"cancel": {"id"},
	"list":   {"scope-id"},
}

func (c *Command) Help() string {
	helpMap := common.HelpMap("session")
	var helpStr string
	switch c.Func {
	case "":
		return base.WrapForHelpText([]string{
			"Usage: boundary sessions [sub command] [options] [args]",
			"",
			"  This command allows operations on Boundary sessions.",
			"",
			"    Read a session:",
			"",
			`      $ boundary sessions read -id s_1234567890`,
			"",
			"  Please see the sessions subcommand help for detailed usage information.",
		})
	case "cancel":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary sessions cancel [options] [args]",
			"",
			"  Cancel the session specified by ID. Example:",
			"",
			`    $ boundary sessions cancel -id s_1234567890`,
			"",
			"",
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
		common.PopulateCommonFlags(c.Command, f, resource.Session.String(), flagsMap[c.Func])
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

	sessionClient := sessions.NewClient(client)

	var result api.GenericResult
	var listResult api.GenericListResult

	switch c.Func {
	case "read":
		result, err = sessionClient.Read(c.Context, c.FlagId)
	case "cancel":
		result, err = sessionClient.Cancel(c.Context, c.FlagId, 0, sessions.WithAutomaticVersioning(true))
	case "list":
		listResult, err = sessionClient.List(c.Context, c.FlagScopeId)
	}

	plural := "session"
	if c.Func == "list" {
		plural = "sessions"
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
	case "list":
		listedSessions := listResult.GetItems().([]*sessions.Session)
		switch base.Format(c.UI) {
		case "json":
			if len(listedSessions) == 0 {
				c.UI.Output("null")
				return 0
			}
			b, err := base.JsonFormatter{}.Format(listedSessions)
			if err != nil {
				c.UI.Error(fmt.Errorf("Error formatting as JSON: %w", err).Error())
				return 1
			}
			c.UI.Output(string(b))

		case "table":
			if len(listedSessions) == 0 {
				c.UI.Output("No auth tokens found")
				return 0
			}
			var output []string
			output = []string{
				"",
				"Session information:",
			}
			for i, t := range listedSessions {
				if i > 0 {
					output = append(output, "")
				}
				output = append(output,
					fmt.Sprintf("  ID:                 %s", t.Id),
					fmt.Sprintf("    Status:           %s", t.Status),
					fmt.Sprintf("    Created Time:     %s", t.CreatedTime.Local().Format(time.RFC1123)),
					fmt.Sprintf("    Expiration Time:  %s", t.ExpirationTime.Local().Format(time.RFC1123)),
					fmt.Sprintf("    Updated Time:     %s", t.UpdatedTime.Local().Format(time.RFC1123)),
					fmt.Sprintf("    User ID:          %s", t.UserId),
					fmt.Sprintf("    Target ID:        %s", t.TargetId),
				)
			}
			c.UI.Output(base.WrapForHelpText(output))
		}
		return 0
	}

	sess := result.GetItem().(*sessions.Session)
	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(generateSessionTableOutput(sess))
	case "json":
		b, err := base.JsonFormatter{}.Format(sess)
		if err != nil {
			c.UI.Error(fmt.Errorf("Error formatting as JSON: %w", err).Error())
			return 1
		}
		c.UI.Output(string(b))
	}

	return 0
}
