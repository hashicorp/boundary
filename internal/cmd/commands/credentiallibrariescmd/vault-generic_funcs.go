// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package credentiallibrariescmd

import (
	"github.com/hashicorp/boundary/api/credentiallibraries"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
)

func init() {
	extraVaultGenericFlagsFunc = extraVaultGenericFlagsFuncImpl
	extraVaultGenericActionsFlagsMapFunc = extraVaultGenericActionsFlagsMapFuncImpl
	extraVaultGenericFlagsHandlingFunc = extraVaultGenericFlagHandlingFuncImpl
}

const (
	pathFlagName              = "vault-path"
	httpMethodFlagName        = "vault-http-method"
	httpRequestBodyFlagName   = "vault-http-request-body"
	credentialTypeFlagName    = "credential-type"
	credentialMappingFlagName = "credential-mapping-override"
)

type extraVaultGenericCmdVars struct {
	flagPath              string
	flagHttpMethod        string
	flagHttpRequestBody   string
	flagCredentialType    string
	flagCredentialMapping []base.CombinedSliceFlagValue
}

func extraVaultGenericActionsFlagsMapFuncImpl() map[string][]string {
	flags := map[string][]string{
		"create": {
			pathFlagName,
			httpMethodFlagName,
			httpRequestBodyFlagName,
			credentialTypeFlagName,
			credentialMappingFlagName,
		},
		"update": {
			pathFlagName,
			httpMethodFlagName,
			httpRequestBodyFlagName,
			credentialMappingFlagName,
		},
	}
	return flags
}

func extraVaultGenericFlagsFuncImpl(c *VaultGenericCommand, set *base.FlagSets, _ *base.FlagSet) {
	f := set.NewFlagSet("Vault Credential Library Options")

	for _, name := range flagsVaultGenericMap[c.Func] {
		switch name {
		case pathFlagName:
			f.StringVar(&base.StringVar{
				Name:   pathFlagName,
				Target: &c.flagPath,
				Usage:  "The path in vault to request credentials from.",
			})
		case httpMethodFlagName:
			f.StringVar(&base.StringVar{
				Name:   httpMethodFlagName,
				Target: &c.flagHttpMethod,
				Usage:  "The http method the library should use when communicating with vault.",
			})
		case httpRequestBodyFlagName:
			f.StringVar(&base.StringVar{
				Name:   httpRequestBodyFlagName,
				Target: &c.flagHttpRequestBody,
				Usage:  "The http request body the library uses to communicate with vault. This can be the value itself, refer to a file on disk (file://) from which the value will be read, or an env var (env://) from which the value will be read.",
			})
		case credentialTypeFlagName:
			f.StringVar(&base.StringVar{
				Name:   credentialTypeFlagName,
				Target: &c.flagCredentialType,
				Usage:  "The type of credential this library will issue, defaults to Unspecified.",
			})
		case credentialMappingFlagName:
			f.CombinationSliceVar(&base.CombinationSliceVar{
				Name:    credentialMappingFlagName,
				Target:  &c.flagCredentialMapping,
				KvSplit: true,
				Usage:   "The credential mapping override.",
			})
		}
	}
}

func extraVaultGenericFlagHandlingFuncImpl(c *VaultGenericCommand, _ *base.FlagSets, opts *[]credentiallibraries.Option) bool {
	switch c.flagPath {
	case "":
	default:
		*opts = append(*opts, credentiallibraries.WithVaultCredentialLibraryPath(c.flagPath))
	}
	switch c.flagHttpMethod {
	case "":
	case "null":
		*opts = append(*opts, credentiallibraries.DefaultVaultCredentialLibraryHttpMethod())
	default:
		*opts = append(*opts, credentiallibraries.WithVaultCredentialLibraryHttpMethod(c.flagHttpMethod))
	}
	switch c.flagHttpRequestBody {
	case "":
	case "null":
		*opts = append(*opts, credentiallibraries.DefaultVaultCredentialLibraryHttpRequestBody())
	default:
		rb, _ := parseutil.ParsePath(c.flagHttpRequestBody)
		*opts = append(*opts, credentiallibraries.WithVaultCredentialLibraryHttpRequestBody(rb))
	}
	switch c.flagCredentialType {
	case "":
	case "null":
		*opts = append(*opts, credentiallibraries.DefaultCredentialType())
	default:
		*opts = append(*opts, credentiallibraries.WithCredentialType(c.flagCredentialType))
	}
	switch len(c.flagCredentialMapping) {
	case 0:
	case 1:
		if len(c.flagCredentialMapping[0].Keys) == 1 && c.flagCredentialMapping[0].Keys[0] == "null" && c.flagCredentialMapping[0].Value == nil {
			*opts = append(*opts, credentiallibraries.DefaultCredentialMappingOverrides())
			break
		}
		fallthrough
	default:
		mappings := make(map[string]any, len(c.flagCredentialMapping))
		for _, mapping := range c.flagCredentialMapping {
			switch {
			case len(mapping.Keys) != 1 || mapping.Keys[0] == "" || mapping.Value == nil || mapping.Value.GetValue() == "":
				// mapping override does not support key segments (e.g. 'x.y=z')
				c.UI.Error("Credential mapping override must be in the format 'key=value', 'key=null' to clear field or 'null' to clear all.")
				return false
			case mapping.Value.GetValue() == "null":
				// user provided 'key=null' indicating the field specific override should
				// be cleared, set map value to nil
				mappings[mapping.Keys[0]] = nil
			default:
				mappings[mapping.Keys[0]] = mapping.Value.GetValue()
			}
		}
		*opts = append(*opts, credentiallibraries.WithCredentialMappingOverrides(mappings))
	}

	return true
}

func (c *VaultGenericCommand) extraVaultGenericHelpFunc(_ map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary credential-libraries create vault -credential-store-id [options] [args]",
			"",
			"  Create a vault-generic-type credential library. Example:",
			"",
			`    $ boundary credential-libraries create vault-generic -credential-store-id csvlt_1234567890 -vault-path "/some/path"`,
			"",
			"",
		})

	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary credential-libraries update vault [options] [args]",
			"",
			"  Update a vault-generic-type credential library given its ID. Example:",
			"",
			`    $ boundary credential-libraries update vault-generic -id clvlt_1234567890 -name devops -description "For DevOps usage"`,
			"",
			"",
		})
	}
	return helpStr + c.Flags().Help()
}
