package roles

import (
	"fmt"

	"github.com/hashicorp/watchtower/internal/cmd/base"
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

	_ = client
	return 0
	/*
		role := &roles.Role{
			Client: client,
		}
		ctx := context.Background()

		// note: Authenticate() calls SetToken() under the hood to set the
		// auth bearer on the client so we do not need to do anything with the
		// returned token after this call, so we ignore it
		result, apiErr, err := org.Authenticate(ctx, c.flagMethodId, c.flagName, c.flagPassword)
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error trying to perform authentication: %s", err.Error()))
			return 2
		}
		if apiErr != nil {
			c.UI.Error(fmt.Sprintf("Error from server when performing authentication: %s", pretty.Sprint(apiErr)))
			return 1
		}

		switch base.Format(c.UI) {
		case "table":
			c.UI.Output(base.WrapForHelpText([]string{
				"",
				"Authentication information:",
				fmt.Sprintf("  Token:           %s", result.Token),
				fmt.Sprintf("  User ID:         %s", result.UserId),
				fmt.Sprintf("  Expiration Time: %s", result.ExpirationTime.Local().Format(time.RFC3339)),
			}))
		}

		tokenName := "default"
		if c.Command.FlagTokenName != "" {
			tokenName = c.Command.FlagTokenName
		}
		if tokenName != "none" {
			if err := keyring.Set("HashiCorp Watchtower Auth Token", tokenName, result.Token); err != nil {
				c.UI.Error(fmt.Sprintf("Error saving auth token to system credential store: %s", err))
				return 1
			}
		}

		return 0
	*/
}
