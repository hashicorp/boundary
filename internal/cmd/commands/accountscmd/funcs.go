package accountscmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/accounts"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/sdk/strutil"
	"github.com/hashicorp/vault/sdk/helper/password"
)

type extraCmdVars = struct {
	flagPassword        string
	flagCurrentPassword string
	flagNewPassword     string
}

var extraActionsFlagsMap = map[string][]string{
	"change-password": {"id", "current-password", "new-password", "version"},
	"set-password":    {"id", "password", "version"},
}

func (c *Command) extraSynopsisFunc() string {
	switch c.Func {
	case "change-password":
		return "Change the password on an account resource"

	case "set-password":
		return "Directly set the password on an account resource"

	default:
		return ""
	}
}

func (c *Command) extraHelpFunc(helpMap map[string]func() string) string {
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
	case "change-password":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary accounts change-password [sub command] [options] [args]",
			"",
			"  This command allows changing the password (with verification of the current password) on account-type resources, if the types match and the operation is allowed by the given account type. Example:",
			"",
			"    Change the password on a password-type account:",
			"",
			`      $ boundary accounts change-password -id apw_1234567890 -current-password <empty, to be read by stdin> -new-password <empty, to be read by stdin>`,
			"",
			"",
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
			"",
			"",
		})
	}
	return helpStr + c.Flags().Help()
}

func (c *Command) extraFlagsFunc(f *base.FlagSet) {
	for _, name := range flagsMap[c.Func] {
		switch name {
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
}

func (c *Command) extraFlagHandlingFunc(opts *[]accounts.Option) int {
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

	return 0
}

func (c *Command) executeExtraActions(origResult api.GenericResult, origError error, accountClient *accounts.Client, version uint32, opts []accounts.Option) (api.GenericResult, error) {
	switch c.Func {
	case "set-password":
		return accountClient.SetPassword(c.Context, c.FlagId, c.flagPassword, version, opts...)
	case "change-password":
		return accountClient.ChangePassword(c.Context, c.FlagId, c.flagCurrentPassword, c.flagNewPassword, version, opts...)
	}
	return origResult, origError
}

func (c *Command) printListTable(items []*accounts.Account) string {
	if len(items) == 0 {
		return "No accounts found"
	}
	var output []string
	output = []string{
		"",
		"Account information:",
	}
	for i, m := range items {
		if i > 0 {
			output = append(output, "")
		}
		if true {
			output = append(output,
				fmt.Sprintf("  ID:                    %s", m.Id),
				fmt.Sprintf("    Version:             %d", m.Version),
				fmt.Sprintf("    Type:                %s", m.Type),
			)
		}
		if m.Name != "" {
			output = append(output,
				fmt.Sprintf("    Name:                %s", m.Name),
			)
		}
		if m.Description != "" {
			output = append(output,
				fmt.Sprintf("    Description:         %s", m.Description),
			)
		}
		if len(m.AuthorizedActions) > 0 {
			output = append(output,
				"    Authorized Actions:",
				base.WrapSlice(6, m.AuthorizedActions),
			)
		}
	}

	return base.WrapForHelpText(output)
}

func printItemTable(item *accounts.Account) string {
	nonAttributeMap := map[string]interface{}{
		"ID":             item.Id,
		"Version":        item.Version,
		"Type":           item.Type,
		"Created Time":   item.CreatedTime.Local().Format(time.RFC1123),
		"Updated Time":   item.UpdatedTime.Local().Format(time.RFC1123),
		"Auth Method ID": item.AuthMethodId,
	}

	if item.Name != "" {
		nonAttributeMap["Name"] = item.Name
	}
	if item.Description != "" {
		nonAttributeMap["Description"] = item.Description
	}

	maxLength := base.MaxAttributesLength(nonAttributeMap, item.Attributes, keySubstMap)

	ret := []string{
		"",
		"Account information:",
		base.WrapMap(2, maxLength+2, nonAttributeMap),
		"",
		"  Scope:",
		base.ScopeInfoForOutput(item.Scope, maxLength),
	}

	if len(item.AuthorizedActions) > 0 {
		ret = append(ret,
			"",
			"  Authorized Actions:",
			base.WrapSlice(4, item.AuthorizedActions),
		)
	}

	if len(item.Attributes) > 0 {
		ret = append(ret,
			"",
			"  Attributes:",
			base.WrapMap(4, maxLength, item.Attributes),
		)
	}

	return base.WrapForHelpText(ret)
}

var keySubstMap = map[string]string{
	"login_name": "Login Name",
}
