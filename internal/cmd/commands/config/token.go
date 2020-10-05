package config

import (
	"fmt"

	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var _ cli.Command = (*TokenCommand)(nil)
var _ cli.CommandAutocomplete = (*TokenCommand)(nil)

type TokenCommand struct {
	*base.Command

	Func string

	flagUserId       bool
	flagAccountId    bool
	flagAuthMethodId bool
}

func (c *TokenCommand) Synopsis() string {
	return fmt.Sprintf("Get the stored token, or its properties")
}

func (c *TokenCommand) Help() string {
	var args []string
	switch c.Func {
	case "get-token":
		args = append(args,
			"Usage: boundary config get-token [options] [args]",
			"",
			"  Fetch a token stored by the Boundary CLI. Example:",
			"",
			`    $ boundary config get-token`,
			"",
			"  This can be useful in various situations. For example, a line such as the following could be in a shell script shared by developers, such that each developer on their own machine executing the script ends up using their own Boundary token:",
			"",
			`    $ curl -H "Authorization: Bearer $(boundary config get-token)" -H "Content-Type: application/json" http://127.0.0.1:9200/v1/roles/r_1234567890`,
			"",
			"  Note that this command keeps parity with the behavior of other Boundary commands; if the BOUNDARY_TOKEN environment variable it set, it will override the value loaded from the system store. Not only does this keep parity, but it also allows examples such as the one above to work even if there is no stored token but if an environment variable is specified.",
			"",
		)
	}

	return base.WrapForHelpText(args) + c.Flags().Help()
}

func (c *TokenCommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetNone)

	f := set.NewFlagSet("Command Options")

	f.StringVar(&base.StringVar{
		Name:   "token-name",
		Target: &c.FlagTokenName,
		EnvVar: base.EnvTokenName,
		Usage:  `If specified, the given value will be used as the name when loading the token from the system credential store. This must correspond to a name used when authenticating.`,
	})

	f.BoolVar(&base.BoolVar{
		Name:   "user-id",
		Target: &c.flagUserId,
		Usage:  `If specified, print out the user ID associated with the token instead of the token itself.`,
	})

	f.BoolVar(&base.BoolVar{
		Name:   "account-id",
		Target: &c.flagAccountId,
		Usage:  `If specified, print out the account ID associated with the token instead of the token itself.`,
	})

	f.BoolVar(&base.BoolVar{
		Name:   "auth-method-id",
		Target: &c.flagAuthMethodId,
		Usage:  `If specified, print out the auth method ID associated with the token instead of the token itself.`,
	})

	return set
}

func (c *TokenCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictAnything
}

func (c *TokenCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *TokenCommand) Run(args []string) (ret int) {
	f := c.Flags()
	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	var optCount int
	if c.flagUserId {
		optCount++
	}
	if c.flagAccountId {
		optCount++
	}
	if c.flagAuthMethodId {
		optCount++
	}

	if optCount > 1 {
		c.UI.Error("Only zero or one output option can be specified.")
		return 1
	}

	// Read from keyring first
	var authToken *authtokens.AuthToken
	tokenName := "default"
	if c.FlagTokenName != "" {
		tokenName = c.FlagTokenName
	}
	if tokenName != "none" {
		at := c.ReadTokenFromKeyring(tokenName)
		if at != nil {
			authToken = at
		}
	}

	if authToken == nil {
		// Fallback to env/CLI
		client, err := c.Client()
		if err != nil {
			c.UI.Error(err.Error())
			return 1
		}
		authToken = &authtokens.AuthToken{Token: client.Token()}
	}

	switch {
	case c.flagUserId:
		if authToken.UserId == "" {
			return 1
		}
		c.UI.Output(authToken.UserId)

	case c.flagAccountId:
		if authToken.AccountId == "" {
			return 1
		}
		c.UI.Output(authToken.AccountId)

	case c.flagAuthMethodId:
		if authToken.AuthMethodId == "" {
			return 1
		}
		c.UI.Output(authToken.AuthMethodId)

	default:
		if authToken.Token == "" {
			return 1
		}
		c.UI.Output(authToken.Token)
	}

	return 0
}
