// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package credentialscmd

import (
	"fmt"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/credentials"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

const (
	usernameFlagName             = "username"
	passwordFlagName             = "password"
	domainFlagName               = "domain"
	privateKeyFlagName           = "private-key"
	privateKeyPassphraseFlagName = "private-key-passphrase"
	secretFlagName               = "secret"
)

func (c *Command) extraHelpFunc(helpMap map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "":
		return base.WrapForHelpText([]string{
			"Usage: boundary credentials [sub command] [options] [args]",
			"",
			"  This command allows operations on Boundary credential resources. Example:",
			"",
			"    Read a credential:",
			"",
			`      $ boundary credentials read -id cred_1234567890`,
			"",
			"  Please see the credentials subcommand help for detailed usage information.",
		})
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary credentials create [type] [sub command] [options] [args]",
			"",
			"  This command allows create operations on Boundary credential resources. Example:",
			"",
			"    Create a credential:",
			"",
			`      $ boundary credentials create username-password -credential-store-id cs_1234567890 -username user -password pass`,
			"",
			"  Please see the typed subcommand help for detailed usage information.",
		})
	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary credentials update [type] [sub command] [options] [args]",
			"",
			"  This command allows update operations on Boundary credential resources. Example:",
			"",
			"    Update a username/password credential:",
			"",
			`      $ boundary credentials update username-password -id cred_1234567890 -name devops -description "For DevOps usage"`,
			"",
			"  Please see the typed subcommand help for detailed usage information.",
		})
	default:
		helpStr = helpMap["base"]()
	}
	return helpStr + c.Flags().Help()
}

func (c *Command) printListTable(items []*credentials.Credential) string {
	if len(items) == 0 {
		return "No credentials found"
	}

	var output []string
	output = []string{
		"",
		"Credential information:",
	}
	for i, m := range items {
		if i > 0 {
			output = append(output, "")
		}
		if m.Id != "" {
			output = append(output,
				fmt.Sprintf("  ID:                    %s", m.Id),
			)
		} else {
			output = append(output,
				fmt.Sprintf("  ID:                    %s", "(not available)"),
			)
		}
		if m.Version > 0 {
			output = append(output,
				fmt.Sprintf("    Version:             %d", m.Version),
			)
		}
		if m.Type != "" {
			output = append(output,
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

func printItemTable(item *credentials.Credential, resp *api.Response) string {
	nonAttributeMap := map[string]any{}
	if item.Id != "" {
		nonAttributeMap["ID"] = item.Id
	}
	if item.Version != 0 {
		nonAttributeMap["Version"] = item.Version
	}
	if !item.CreatedTime.IsZero() {
		nonAttributeMap["Created Time"] = item.CreatedTime.Local().Format(time.RFC1123)
	}
	if !item.UpdatedTime.IsZero() {
		nonAttributeMap["Updated Time"] = item.UpdatedTime.Local().Format(time.RFC1123)
	}
	if item.CredentialStoreId != "" {
		nonAttributeMap["Credential Store ID"] = item.CredentialStoreId
	}
	if item.Name != "" {
		nonAttributeMap["Name"] = item.Name
	}
	if item.Description != "" {
		nonAttributeMap["Description"] = item.Description
	}
	if item.Type != "" {
		nonAttributeMap["Type"] = item.Type
	}

	maxLength := base.MaxAttributesLength(nonAttributeMap, item.Attributes, keySubstMap)

	ret := []string{
		"",
		"Credential information:",
		base.WrapMap(2, maxLength+2, nonAttributeMap),
	}

	if item.Scope != nil {
		ret = append(ret,
			"",
			"  Scope:",
			base.ScopeInfoForOutput(item.Scope, maxLength),
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
	"username":                    "Username",
	"password_hmac":               "Password HMAC",
	"domain":                      "Domain",
	"private_key_hmac":            "Private Key HMAC",
	"private_key_passphrase_hmac": "Private Key Passphrase HMAC",
}
