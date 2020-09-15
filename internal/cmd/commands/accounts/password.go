package accounts

import (
	"fmt"
	"net/textproto"
	"os"
	"strings"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/accounts"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/common"
	"github.com/hashicorp/boundary/sdk/strutil"
	"github.com/hashicorp/vault/sdk/helper/password"
	"github.com/kr/pretty"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var _ cli.Command = (*PasswordCommand)(nil)
var _ cli.CommandAutocomplete = (*PasswordCommand)(nil)

type PasswordCommand struct {
	*base.Command

	Func string

	flagAuthMethodId string
	flagLoginName    string
	flagPassword     string
}

func (c *PasswordCommand) Synopsis() string {
	return fmt.Sprintf("%s a password-type account within Boundary", textproto.CanonicalMIMEHeaderKey(c.Func))
}

var passwordFlagsMap = map[string][]string{
	"create": {"auth-method-id", "name", "description", "login-name", "password"},
	"update": {"id", "name", "description", "version"},
}

func (c *PasswordCommand) Help() string {
	var info string
	switch c.Func {
	case "create":
		info = base.WrapForHelpText([]string{
			"Usage: boundary accounts password create [options] [args]",
			"",
			"  Create a password-type account. Example:",
			"",
			`    $ boundary accounts password create -name prodops -description "Password account for ProdOps" -address "127.0.0.1"`,
			"",
			"",
		})

	case "update":
		info = base.WrapForHelpText([]string{
			"Usage: boundary accounts password update [options] [args]",
			"",
			"  Update a password-type account given its ID. Example:",
			"",
			`    $ boundary accounts password update -id hst_1234567890 -name "devops" -description "Password account for DevOps" -address "10.20.30.40"`,
			"",
			"",
		})
	}
	return info + c.Flags().Help()
}

func (c *PasswordCommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)

	f := set.NewFlagSet("Command Options")

	if len(passwordFlagsMap[c.Func]) > 0 {
		common.PopulateCommonFlags(c.Command, f, "password-type account", passwordFlagsMap[c.Func])
	}

	for _, name := range passwordFlagsMap[c.Func] {
		switch name {
		case "auth-method-id":
			f.StringVar(&base.StringVar{
				Name:   "auth-method-id",
				Target: &c.flagAuthMethodId,
				Usage:  "The auth-method resource in which to create or update the account resource",
			})
		}
	}

	f = set.NewFlagSet("Password Account Options")

	for _, name := range passwordFlagsMap[c.Func] {
		switch name {
		case "login-name":
			f.StringVar(&base.StringVar{
				Name:   "login-name",
				Target: &c.flagLoginName,
				Usage:  "The login name for the account",
			})
		case "password":
			f.StringVar(&base.StringVar{
				Name:   "password",
				Target: &c.flagPassword,
				Usage:  "The password for the account. If not specified, the command will prompt for the password to be entered in a non-echoing way.",
			})
		}
	}

	return set
}

func (c *PasswordCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictAnything
}

func (c *PasswordCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *PasswordCommand) Run(args []string) int {
	if c.Func == "" {
		return cli.RunResultHelp
	}

	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	if strutil.StrListContains(passwordFlagsMap[c.Func], "id") && c.FlagId == "" {
		c.UI.Error("ID is required but not passed in via -id")
		return 1
	}
	if strutil.StrListContains(passwordFlagsMap[c.Func], "auth-method-id") && c.flagAuthMethodId == "" {
		c.UI.Error("Auth Method ID must be passed in via -auth-method-id")
		return 1
	}
	if c.Func == "create" && c.flagLoginName == "" {
		c.UI.Error("Login Name must be passed in via -login-name")
		return 1
	}

	client, err := c.Client()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error creating API client: %s", err.Error()))
		return 2
	}

	var opts []accounts.Option

	switch c.FlagName {
	case "":
	case "null":
		opts = append(opts, accounts.DefaultName())
	default:
		opts = append(opts, accounts.WithName(c.FlagName))
	}

	switch c.FlagDescription {
	case "":
	case "null":
		opts = append(opts, accounts.DefaultDescription())
	default:
		opts = append(opts, accounts.WithDescription(c.FlagDescription))
	}

	switch c.flagLoginName {
	case "":
	case "null":
		opts = append(opts, accounts.DefaultPasswordAccountLoginName())
	default:
		opts = append(opts, accounts.WithPasswordAccountLoginName(c.flagLoginName))
	}

	if strutil.StrListContains(passwordFlagsMap[c.Func], "password") {
		switch c.flagPassword {
		case "":
			fmt.Print("Password is not set as flag, please enter it now (will be hidden): ")
			value, err := password.Read(os.Stdin)
			fmt.Print("\n")
			if err != nil {
				c.UI.Error(fmt.Sprintf("An error occurred attempting to read the password. The raw error message is shown below but usually this is because you attempted to pipe a value into the command or you are executing outside of a terminal (TTY). The raw error was:\n\n%s", err.Error()))
				return 2
			}
			opts = append(opts, accounts.WithPasswordAccountPassword(strings.TrimSpace(value)))
		default:
			opts = append(opts, accounts.WithPasswordAccountPassword(c.flagPassword))
		}
	}

	accountClient := accounts.NewClient(client)

	// Perform check-and-set when needed
	var version uint32
	switch c.Func {
	case "create":
		// These don't update so don't need the existing version
	default:
		switch c.FlagVersion {
		case 0:
			opts = append(opts, accounts.WithAutomaticVersioning(true))
		default:
			version = uint32(c.FlagVersion)
		}
	}

	var result api.GenericResult
	var apiErr *api.Error

	switch c.Func {
	case "create":
		result, apiErr, err = accountClient.Create(c.Context, c.flagAuthMethodId, opts...)
	case "update":
		result, apiErr, err = accountClient.Update(c.Context, c.FlagId, version, opts...)
	}

	plural := "password-type account"
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error trying to %s %s: %s", c.Func, plural, err.Error()))
		return 2
	}
	if apiErr != nil {
		c.UI.Error(fmt.Sprintf("Error from controller when performing %s on %s: %s", c.Func, plural, pretty.Sprint(apiErr)))
		return 1
	}

	account := result.GetItem().(*accounts.Account)
	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(generateAccountTableOutput(account))
	case "json":
		b, err := base.JsonFormatter{}.Format(account)
		if err != nil {
			c.UI.Error(fmt.Errorf("Error formatting as JSON: %w", err).Error())
			return 1
		}
		c.UI.Output(string(b))
	}

	return 0
}
