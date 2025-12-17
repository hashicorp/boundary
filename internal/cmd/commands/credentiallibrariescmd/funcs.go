// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package credentiallibrariescmd

import (
	"fmt"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/credentiallibraries"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func (c *Command) extraHelpFunc(helpMap map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "":
		return base.WrapForHelpText([]string{
			"Usage: boundary credential-libraries [sub command] [options] [args]",
			"",
			"  This command allows operations on Boundary credential library resources. Example:",
			"",
			"    Read a credential library:",
			"",
			`      $ boundary credential-libraries read -id clvlt_1234567890`,
			"",
			"  Please see the credential-libraries subcommand help for detailed usage information.",
		})
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary credential-libraries create [type] [sub command] [options] [args]",
			"",
			"  This command allows create operations on Boundary credential library resources. Example:",
			"",
			"    Create a credential library:",
			"",
			`      $ boundary credential-libraries create vault -credential-store-id csvlt_1234567890 -vault-path "/some/path"`,
			"",
			"  Please see the typed subcommand help for detailed usage information.",
		})
	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary credential-libraries update [type] [sub command] [options] [args]",
			"",
			"  This command allows update operations on Boundary credential library resources. Example:",
			"",
			"    Update a vault-type credential library:",
			"",
			`      $ boundary credential-libraries update vault -id clvlt_1234567890 -name devops -description "For DevOps usage"`,
			"",
			"  Please see the typed subcommand help for detailed usage information.",
		})
	default:
		helpStr = helpMap["base"]()
	}
	return helpStr + c.Flags().Help()
}

func (c *Command) printListTable(items []*credentiallibraries.CredentialLibrary) string {
	if len(items) == 0 {
		return "No credential library found"
	}

	var output []string
	output = []string{
		"",
		"Credential Library information:",
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
		if m.CredentialType != "" {
			output = append(output,
				fmt.Sprintf("    Credential Type:     %s", m.CredentialType),
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

func printItemTable(item *credentiallibraries.CredentialLibrary, resp *api.Response) string {
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

	var keySubstMap map[string]string
	switch item.Type {
	case "vault":
		fallthrough
	case "vault-generic":
		keySubstMap = genericKeySubstMap
	case "vault-ssh-certificate":
		keySubstMap = sshCertKeySubstMap
	case "vault-ldap":
		keySubstMap = ldapKeySubstMap
	}

	maxLength := base.MaxAttributesLength(nonAttributeMap, item.Attributes, keySubstMap)

	ret := []string{
		"",
		"Credential Library information:",
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

	if item.CredentialType != "" {
		ret = append(ret,
			"",
			"  Credential Type:",
			fmt.Sprintf("    %v", item.CredentialType),
		)
		if len(item.CredentialMappingOverrides) > 0 {
			ret = append(ret,
				"  Credential Mapping Overrides:",
				base.WrapMap(4, maxLength, item.CredentialMappingOverrides),
			)
		}
	}

	return base.WrapForHelpText(ret)
}

var genericKeySubstMap = map[string]string{
	"path":              "Path",
	"http_method":       "HTTP Method",
	"http_request_body": "HTTP Request Body",
}

var sshCertKeySubstMap = map[string]string{
	"path":             "Path",
	"username":         "Username",
	"key_type":         "Key Type",
	"key_bits":         "Key Bits",
	"ttl":              "TTL",
	"key_id":           "Key ID",
	"critical_options": "Critical Options",
	"extensions":       "Extensions",
}

var ldapKeySubstMap = map[string]string{
	"path": "Path",
}
