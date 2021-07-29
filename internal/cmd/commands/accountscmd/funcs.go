package accountscmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/accounts"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/go-secure-stdlib/password"
	"github.com/hashicorp/go-secure-stdlib/strutil"
)

func init() {
	extraActionsFlagsMapFunc = extraActionsFlagsMapFuncImpl
	extraSynopsisFunc = extraSynopsisFuncImpl
	extraFlagsFunc = extraFlagsFuncImpl
	extraFlagsHandlingFunc = extraFlagsHandlingFuncImpl
	executeExtraActions = executeExtraActionsImpl
}

type extraCmdVars struct {
	flagPassword        string
	flagCurrentPassword string
	flagNewPassword     string
}

func extraActionsFlagsMapFuncImpl() map[string][]string {
	return map[string][]string{
		"change-password": {"id", "current-password", "new-password", "version"},
		"set-password":    {"id", "password", "version"},
	}
}

func extraSynopsisFuncImpl(c *Command) string {
	switch c.Func {
	case "change-password":
		return "Change the password on an account"

	case "set-password":
		return "Directly set the password on an account"

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
			`      $ boundary accounts read -id acctpw_1234567890`,
			"",
			"  Please see the accounts subcommand help for detailed usage information.",
		})
	case "change-password":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary accounts change-password [options] [args]",
			"",
			"  This command allows changing the password (with verification of the current password) on account-type resources, if the types match and the operation is allowed by the given account type. Example:",
			"",
			"    Change the password on a password-type account:",
			"",
			`      $ boundary accounts change-password -id acctpw_1234567890 -current-password <empty, to be read by stdin> -new-password <empty, to be read by stdin>`,
			"",
			"",
		})
	case "set-password":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary accounts set-password [options] [args]",
			"",
			"  This command allows setting the password on account-type resources, if the types match and the operation is allowed by the given account type. Example:",
			"",
			"    Set the password on a password-type account:",
			"",
			`      $ boundary accounts set-password -id acctpw_1234567890 -password <empty, to be read by stdin>`,
			"",
			"",
		})
	}
	return helpStr + c.Flags().Help()
}

func extraFlagsFuncImpl(c *Command, _ *base.FlagSets, f *base.FlagSet) {
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

func extraFlagsHandlingFuncImpl(c *Command, _ *base.FlagSets, opts *[]accounts.Option) bool {
	if strutil.StrListContains(flagsMap[c.Func], "password") && c.flagPassword == "" {
		fmt.Print("Password is not set as flag, please enter it now (will be hidden): ")
		value, err := password.Read(os.Stdin)
		fmt.Print("\n")
		if err != nil {
			c.UI.Error(fmt.Sprintf("An error occurred attempting to read the password. The raw error message is shown below but usually this is because you attempted to pipe a value into the command or you are executing outside of a terminal (TTY). The raw error was:\n\n%s", err.Error()))
			return false
		}
		fmt.Print("Please enter it one more time for confirmation: ")
		confirmation, err := password.Read(os.Stdin)
		fmt.Print("\n")
		if err != nil {
			c.UI.Error(fmt.Sprintf("An error occurred attempting to read the password. The raw error message is shown below but usually this is because you attempted to pipe a value into the command or you are executing outside of a terminal (TTY). The raw error was:\n\n%s", err.Error()))
			return false
		}
		if strings.TrimSpace(value) != strings.TrimSpace(confirmation) {
			c.UI.Error("Entered password and confirmation value did not match.")
			return false
		}
		c.flagPassword = strings.TrimSpace(value)
	}

	if strutil.StrListContains(flagsMap[c.Func], "current-password") && c.flagCurrentPassword == "" {
		fmt.Print("Current password is not set as flag, please enter it now (will be hidden): ")
		value, err := password.Read(os.Stdin)
		fmt.Print("\n")
		if err != nil {
			c.UI.Error(fmt.Sprintf("An error occurred attempting to read the password. The raw error message is shown below but usually this is because you attempted to pipe a value into the command or you are executing outside of a terminal (TTY). The raw error was:\n\n%s", err.Error()))
			return false
		}
		fmt.Print("Please enter it one more time for confirmation: ")
		confirmation, err := password.Read(os.Stdin)
		fmt.Print("\n")
		if err != nil {
			c.UI.Error(fmt.Sprintf("An error occurred attempting to read the password. The raw error message is shown below but usually this is because you attempted to pipe a value into the command or you are executing outside of a terminal (TTY). The raw error was:\n\n%s", err.Error()))
			return false
		}
		if strings.TrimSpace(value) != strings.TrimSpace(confirmation) {
			c.UI.Error("Entered password and confirmation value did not match.")
			return false
		}
		c.flagCurrentPassword = strings.TrimSpace(value)
	}

	if strutil.StrListContains(flagsMap[c.Func], "new-password") && c.flagNewPassword == "" {
		fmt.Print("New password is not set as flag, please enter it now (will be hidden): ")
		value, err := password.Read(os.Stdin)
		fmt.Print("\n")
		if err != nil {
			c.UI.Error(fmt.Sprintf("An error occurred attempting to read the password. The raw error message is shown below but usually this is because you attempted to pipe a value into the command or you are executing outside of a terminal (TTY). The raw error was:\n\n%s", err.Error()))
			return false
		}
		c.flagNewPassword = strings.TrimSpace(value)
	}

	return true
}

func executeExtraActionsImpl(c *Command, origResult api.GenericResult, origError error, accountClient *accounts.Client, version uint32, opts []accounts.Option) (api.GenericResult, error) {
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
	for i, item := range items {
		if i > 0 {
			output = append(output, "")
		}
		if item.Id != "" {
			output = append(output,
				fmt.Sprintf("  ID:                    %s", item.Id),
			)
		} else {
			output = append(output,
				fmt.Sprintf("  ID:                    %s", "(not available)"),
			)
		}
		if item.Version > 0 {
			output = append(output,
				fmt.Sprintf("    Version:             %d", item.Version),
			)
		}
		if item.Type != "" {
			output = append(output,
				fmt.Sprintf("    Type:                %s", item.Type),
			)
		}
		if item.Name != "" {
			output = append(output,
				fmt.Sprintf("    Name:                %s", item.Name),
			)
		}
		if item.Description != "" {
			output = append(output,
				fmt.Sprintf("    Description:         %s", item.Description),
			)
		}
		if len(item.AuthorizedActions) > 0 {
			output = append(output,
				"    Authorized Actions:",
				base.WrapSlice(6, item.AuthorizedActions),
			)
		}
	}

	return base.WrapForHelpText(output)
}

func printItemTable(result api.GenericResult) string {
	item := result.GetItem().(*accounts.Account)
	nonAttributeMap := map[string]interface{}{}
	if item.Id != "" {
		nonAttributeMap["ID"] = item.Id
	}
	if item.Version != 0 {
		nonAttributeMap["Version"] = item.Version
	}
	if item.Type != "" {
		nonAttributeMap["Type"] = item.Type
	}
	if !item.CreatedTime.IsZero() {
		nonAttributeMap["Created Time"] = item.CreatedTime.Local().Format(time.RFC1123)
	}
	if !item.UpdatedTime.IsZero() {
		nonAttributeMap["Updated Time"] = item.UpdatedTime.Local().Format(time.RFC1123)
	}
	if item.AuthMethodId != "" {
		nonAttributeMap["Auth Method ID"] = item.AuthMethodId
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
	}

	if item.Scope != nil {
		ret = append(ret,
			"",
			"  Scope:",
			base.ScopeInfoForOutput(item.Scope, maxLength),
		)
	}

	if len(item.ManagedGroupIds) > 0 {
		ret = append(ret,
			"",
			"  Managed Group IDs:",
			base.WrapSlice(4, item.ManagedGroupIds),
		)
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
