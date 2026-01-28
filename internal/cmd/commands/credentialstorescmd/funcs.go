// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package credentialstorescmd

import (
	"fmt"
	"sort"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/credentialstores"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func (c *Command) extraHelpFunc(helpMap map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "":
		return base.WrapForHelpText([]string{
			"Usage: boundary credential-stores [sub command] [options] [args]",
			"",
			"  This command allows operations on Boundary credential store resources. Example:",
			"",
			"    Read a credential store:",
			"",
			`      $ boundary credential-stores read -id csvlt_1234567890`,
			"",
			"  Please see the credential-stores subcommand help for detailed usage information.",
		})
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary credential-stores create [type] [sub command] [options] [args]",
			"",
			"  This command allows create operations on Boundary credential store resources. Example:",
			"",
			"    Create a vault-type credential store:",
			"",
			`      $ boundary credential-stores create vault -scope-id p_1234567890 -vault-address "http://localhost:8200" -vault-token "s.s0m3t0k3n"`,
			"",
			"    Create a static-type credential store:",
			"",
			`      $ boundary credential-stores create static -scope-id p_1234567890`,
			"",
			"  Please see the typed subcommand help for detailed usage information.",
		})
	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary credential-stores update [type] [sub command] [options] [args]",
			"",
			"  This command allows update operations on Boundary credential store resources. Example:",
			"",
			"    Update a vault-type credential store:",
			"",
			`      $ boundary credential-stores update vault -id csvlt_1234567890 -name devops -description "For DevOps usage"`,
			"",
			"    Update a static-type credential store:",
			"",
			`      $ boundary credential-stores update static -id cs_1234567890 -name devops -description "For DevOps usage"`,
			"",
			"  Please see the typed subcommand help for detailed usage information.",
		})
	default:
		helpStr = helpMap["base"]()
	}
	return helpStr + c.Flags().Help()
}

func (c *Command) printListTable(items []*credentialstores.CredentialStore) string {
	if len(items) == 0 {
		return "No credential store found"
	}

	var output []string
	output = []string{
		"",
		"Credential Store information:",
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
		if c.FlagRecursive && m.ScopeId != "" {
			output = append(output,
				fmt.Sprintf("    Scope ID:            %s", m.ScopeId),
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

func printItemTable(item *credentialstores.CredentialStore, resp *api.Response) string {
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
		"Credential Store information:",
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

	if len(item.AuthorizedCollectionActions) > 0 {
		keys := make([]string, 0, len(item.AuthorizedCollectionActions))
		for k := range item.AuthorizedCollectionActions {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		ret = append(ret, "",
			"  Authorized Actions on Credential Store's Collections:",
		)
		for _, key := range keys {
			ret = append(ret,
				fmt.Sprintf("    %s:", key),
				base.WrapSlice(6, item.AuthorizedCollectionActions[key]),
			)
		}
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
	"address":                     "Address",
	"namespace":                   "Namespace",
	"ca_cert":                     "CA Cert",
	"tls_server_name":             "TLS Server Name",
	"tls_skip_verify":             "Skip TLS Verification",
	"token_hmac":                  "Token HMAC",
	"token_status":                "Token Status",
	"client_certificate":          "Client Certificate",
	"client_certificate_key_hmac": "Client Certificate Key HMAC",
	"worker_filter":               "Worker Filter",
}
