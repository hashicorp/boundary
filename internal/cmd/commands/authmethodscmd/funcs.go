package authmethodscmd

import (
	"fmt"
	"sort"
	"time"

	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func init() {
	extraOidcSynopsisFunc = extraSynopsisFuncImpl
}

func (c *Command) extraHelpFunc(helpMap map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "":
		return base.WrapForHelpText([]string{
			"Usage: boundary auth-methods [sub command] [options] [args]",
			"",
			"  This command allows operations on Boundary auth method resources. Example:",
			"",
			"    Read an auth method:",
			"",
			`      $ boundary auth-methods read -id ampw_1234567890`,
			"",
			"  Please see the auth-methods subcommand help for detailed usage information.",
		})
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary auth-methods create [type] [sub command] [options] [args]",
			"",
			"  This command allows create operations on Boundary auth method resources. Example:",
			"",
			"    Create a password-type auth method:",
			"",
			`      $ boundary auth-methods create password -name prodops -description "For ProdOps usage"`,
			"",
			"  Please see the typed subcommand help for detailed usage information.",
		})
	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary auth-methods update [type] [sub command] [options] [args]",
			"",
			"  This command allows update operations on Boundary auth method resources. Example:",
			"",
			"    Update a password-type auth method:",
			"",
			`      $ boundary auth-methods update password -id ampw_1234567890 -name devops -description "For DevOps usage"`,
			"",
			"  Please see the typed subcommand help for detailed usage information.",
		})
	}
	return helpStr + c.Flags().Help()
}

func extraSynopsisFuncImpl(c *OidcCommand) string {
	switch c.Func {
	case "change-state":
		return "Change the active state of an auth method"

	default:
		return ""
	}
}

func (c *Command) printListTable(items []*authmethods.AuthMethod) string {
	if len(items) == 0 {
		return "No auth methods found"
	}

	var output []string
	output = []string{
		"",
		"Auth Method information:",
	}
	for i, m := range items {
		if i > 0 {
			output = append(output, "")
		}
		if true {
			output = append(output,
				fmt.Sprintf("  ID:                     %s", m.Id),
			)
		}
		if c.FlagRecursive {
			output = append(output,
				fmt.Sprintf("    Scope ID:             %s", m.Scope.Id),
			)
		}
		if true {
			output = append(output,
				fmt.Sprintf("    Version:              %d", m.Version),
				fmt.Sprintf("    Type:                 %s", m.Type),
			)
		}
		if m.Name != "" {
			output = append(output,
				fmt.Sprintf("    Name:                 %s", m.Name),
			)
		}
		if m.Description != "" {
			output = append(output,
				fmt.Sprintf("    Description:          %s", m.Description),
			)
		}
		if true {
			output = append(output,
				fmt.Sprintf("    Is Primary For Scope: %t", m.IsPrimary),
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

func printItemTable(in *authmethods.AuthMethod) string {
	nonAttributeMap := map[string]interface{}{
		"ID":                   in.Id,
		"Version":              in.Version,
		"Type":                 in.Type,
		"Created Time":         in.CreatedTime.Local().Format(time.RFC1123),
		"Updated Time":         in.UpdatedTime.Local().Format(time.RFC1123),
		"Is Primary For Scope": in.IsPrimary,
	}

	if in.Name != "" {
		nonAttributeMap["Name"] = in.Name
	}
	if in.Description != "" {
		nonAttributeMap["Description"] = in.Description
	}

	maxLength := base.MaxAttributesLength(nonAttributeMap, in.Attributes, keySubstMap)

	ret := []string{
		"",
		"Auth Method information:",
		base.WrapMap(2, maxLength+2, nonAttributeMap),
		"",
		"  Scope:",
		base.ScopeInfoForOutput(in.Scope, maxLength),
	}

	if len(in.AuthorizedActions) > 0 {
		ret = append(ret,
			"",
			"  Authorized Actions:",
			base.WrapSlice(4, in.AuthorizedActions),
		)
	}

	if len(in.AuthorizedCollectionActions) > 0 {
		keys := make([]string, 0, len(in.AuthorizedCollectionActions))
		for k := range in.AuthorizedCollectionActions {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		ret = append(ret,
			"",
			"  Authorized Actions on Auth Method's Collections:",
		)
		for _, key := range keys {
			ret = append(ret,
				fmt.Sprintf("    %s:", key),
				base.WrapSlice(6, in.AuthorizedCollectionActions[key]),
			)
		}
	}

	if len(in.Attributes) > 0 {
		ret = append(ret,
			"",
			"  Attributes:",
			base.WrapMap(4, maxLength, in.Attributes),
		)
	}

	return base.WrapForHelpText(ret)
}

var keySubstMap = map[string]string{
	"min_login_name_length": "Minimum Login Name Length",
	"min_password_length":   "Minimum Password Length",
}
