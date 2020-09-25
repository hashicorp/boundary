package accounts

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/accounts"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/common"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/sdk/strutil"
	"github.com/hashicorp/vault/sdk/helper/password"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var _ cli.Command = (*Command)(nil)
var _ cli.CommandAutocomplete = (*Command)(nil)

type Command struct {
	*base.Command

	Func string

	flagAuthMethodId    string
	flagPassword        string
	flagCurrentPassword string
	flagNewPassword     string
}

func (c *Command) Synopsis() string {
	switch c.Func {
	case "create":
		return "Create account resources within Boundary"
	case "update":
		return "Update account resources within Boundary"
	default:
		return common.SynopsisFunc(c.Func, "account")
	}
}

var flagsMap = map[string][]string{
	"read":            {"id"},
	"delete":          {"id"},
	"list":            {"auth-method-id"},
	"set-password":    {"id", "password", "version"},
	"change-password": {"id", "current-password", "new-password", "version"},
}

func (c *Command) Help() string {
	helpMap := common.HelpMap("account")
	var helpStr string
	switch c.Func {
	case "":
		return base.WrapForHelpText([]string{
			"Usage: boundary accounts [sub command] [options] [args]",
			"",
			"  This command allows operations on Boundary account resources. Example:",
			"",
			"    Read a account:",
			"",
			`      $ boundary accounts read -id apw_1234567890`,
			"",
			"  Please see the accounts subcommand help for detailed usage information.",
		})
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary accounts create [type] [sub command] [options] [args]",
			"",
			"  This command allows create operations on Boundary account resources. Example:",
			"",
			"    Create a password-type account:",
			"",
			`      $ boundary accounts create password -name prodops -description "For ProdOps usage"`,
			"",
			"  Please see the typed subcommand help for detailed usage information.",
		})
	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary accounts update [type] [sub command] [options] [args]",
			"",
			"  This command allows update operations on Boundary account resources. Example:",
			"",
			"    Update a password-type account:",
			"",
			`      $ boundary accounts update password -id apw_1234567890 -name devops -description "For DevOps usage"`,
			"",
			"  Please see the typed subcommand help for detailed usage information.",
		})
	case "set-password":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary accounts set-password [sub command] [options] [args]",
			"",
			"  This command allows setting the password on account-type resources, if the types match and the operation is allowed by the given account type. Example:",
			"",
			"    Set the password on a password-type account:",
			"",
			`      $ boundary accounts set-password -id apw_1234567890 -password <empty, to be read by stdin>`,
		})
	case "change-password":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary accounts change-password [sub command] [options] [args]",
			"",
			"  This command allows changing the password (with verification of the current password) on account-type resources, if the types match and the operation is allowed by the given account type. Example:",
			"",
			"    Change the password on a password-type account:",
			"",
			`      $ boundary accounts change-password -id apw_1234567890 -current-password <empty, to be read by stdin> -new-password <empty, to be read by stdin>`,
		})
	default:
		helpStr = helpMap[c.Func]()
	}
	return helpStr + c.Flags().Help()
}

func (c *Command) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)

	f := set.NewFlagSet("Command Options")

	if len(flagsMap[c.Func]) > 0 {
		common.PopulateCommonFlags(c.Command, f, resource.Account.String(), flagsMap[c.Func])
	}

	for _, name := range flagsMap[c.Func] {
		switch name {
		case "auth-method-id":
			f.StringVar(&base.StringVar{
				Name:   "auth-method-id",
				Target: &c.flagAuthMethodId,
				Usage:  "The auth-method resource in which to create or update the account resource",
			})
		case "password":
			f.StringVar(&base.StringVar{
				Name:   "password",
				Target: &c.flagPassword,
				Usage:  "The password for the account. If not specified, the command will prompt for the password to be entered in a non-echoing way.",
			})
		case "current-password":
			f.StringVar(&base.StringVar{
				Name:   "current-password",
				Target: &c.flagCurrentPassword,
				Usage:  "The current password for the account. If not specified, the command will prompt for the password to be entered in a non-echoing way.",
			})
		case "new-password":
			f.StringVar(&base.StringVar{
				Name:   "new-password",
				Target: &c.flagNewPassword,
				Usage:  "The new password for the account. If not specified, the command will prompt for the password to be entered in a non-echoing way.",
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
	switch c.Func {
	case "", "create", "update":
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
	if strutil.StrListContains(flagsMap[c.Func], "auth-method-id") && c.flagAuthMethodId == "" {
		c.UI.Error("Auth Method ID must be passed in via -auth-method-id")
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

	if strutil.StrListContains(flagsMap[c.Func], "password") && c.flagPassword == "" {
		fmt.Print("Password is not set as flag, please enter it now (will be hidden): ")
		value, err := password.Read(os.Stdin)
		fmt.Print("\n")
		if err != nil {
			c.UI.Error(fmt.Sprintf("An error occurred attempting to read the password. The raw error message is shown below but usually this is because you attempted to pipe a value into the command or you are executing outside of a terminal (TTY). The raw error was:\n\n%s", err.Error()))
			return 2
		}
		c.flagPassword = strings.TrimSpace(value)
	}

	if strutil.StrListContains(flagsMap[c.Func], "current-password") && c.flagCurrentPassword == "" {
		fmt.Print("Current password is not set as flag, please enter it now (will be hidden): ")
		value, err := password.Read(os.Stdin)
		fmt.Print("\n")
		if err != nil {
			c.UI.Error(fmt.Sprintf("An error occurred attempting to read the password. The raw error message is shown below but usually this is because you attempted to pipe a value into the command or you are executing outside of a terminal (TTY). The raw error was:\n\n%s", err.Error()))
			return 2
		}
		c.flagCurrentPassword = strings.TrimSpace(value)
	}

	if strutil.StrListContains(flagsMap[c.Func], "new-password") && c.flagNewPassword == "" {
		fmt.Print("New password is not set as flag, please enter it now (will be hidden): ")
		value, err := password.Read(os.Stdin)
		fmt.Print("\n")
		if err != nil {
			c.UI.Error(fmt.Sprintf("An error occurred attempting to read the password. The raw error message is shown below but usually this is because you attempted to pipe a value into the command or you are executing outside of a terminal (TTY). The raw error was:\n\n%s", err.Error()))
			return 2
		}
		c.flagNewPassword = strings.TrimSpace(value)
	}

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

	accountClient := accounts.NewClient(client)

	existed := true
	var result api.GenericResult
	var listResult api.GenericListResult

	switch c.Func {
	case "read":
		result, err = accountClient.Read(c.Context, c.FlagId, opts...)
	case "delete":
		_, err = accountClient.Delete(c.Context, c.FlagId, opts...)
		if apiErr := api.AsServerError(err); apiErr != nil && apiErr.Status == int32(http.StatusNotFound) {
			existed = false
			err = nil
		}
	case "list":
		listResult, err = accountClient.List(c.Context, c.flagAuthMethodId, opts...)
	case "set-password":
		result, err = accountClient.SetPassword(c.Context, c.FlagId, c.flagPassword, version, opts...)
	case "change-password":
		result, err = accountClient.ChangePassword(c.Context, c.FlagId, c.flagCurrentPassword, c.flagNewPassword, version, opts...)
	}

	plural := "account"
	if c.Func == "list" {
		plural = "accounts"
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
		accounts := listResult.GetItems().([]*accounts.Account)
		switch base.Format(c.UI) {
		case "json":
			if len(accounts) == 0 {
				c.UI.Output("null")
				return 0
			}
			b, err := base.JsonFormatter{}.Format(accounts)
			if err != nil {
				c.UI.Error(fmt.Errorf("Error formatting as JSON: %w", err).Error())
				return 1
			}
			c.UI.Output(string(b))

		case "table":
			if len(accounts) == 0 {
				c.UI.Output("No accounts found")
				return 0
			}
			var output []string
			output = []string{
				"",
				"Account information:",
			}
			for i, m := range accounts {
				if i > 0 {
					output = append(output, "")
				}
				if true {
					output = append(output,
						fmt.Sprintf("  ID:             %s", m.Id),
						fmt.Sprintf("    Version:      %d", m.Version),
						fmt.Sprintf("    Type:         %s", m.Type),
					)
				}
				if m.Name != "" {
					output = append(output,
						fmt.Sprintf("    Name:         %s", m.Name),
					)
				}
				if m.Description != "" {
					output = append(output,
						fmt.Sprintf("    Description:  %s", m.Description),
					)
				}
			}
			c.UI.Output(base.WrapForHelpText(output))
		}
		return 0
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
