// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package credentiallibrariescmd

import (
	"fmt"
	"strconv"

	"github.com/hashicorp/boundary/api/credentiallibraries"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/common"
)

func init() {
	extraVaultSshCertificateFlagsFunc = extraVaultSshCertificateFlagsFuncImpl
	extraVaultSshCertificateActionsFlagsMapFunc = extraVaultSshCertificateActionsFlagsMapFuncImpl
	extraVaultSshCertificateFlagsHandlingFunc = extraVaultSshCertificateFlagHandlingFuncImpl
}

const (
	usernameName                  = "username"
	keyTypeName                   = "key-type"
	keyBitsName                   = "key-bits"
	ttlName                       = "ttl"
	keyIdName                     = "key-id"
	criticalOptionsName           = "critical-options"
	piecewiseCriticalOptionsName  = "critical-option"
	extensionsName                = "extensions"
	piecewiseExtensionName        = "extension"
	additionalValidPrincipalsName = "additional-valid-principal"
)

type extraVaultSshCertificateCmdVars struct {
	flagPath                      string
	flagUsername                  string
	flagKeyType                   string
	flagKeyBits                   string
	flagTtl                       string
	flagKeyId                     string
	flagCriticalOptions           string
	flagCriticalOpts              []base.CombinedSliceFlagValue
	flagExtensions                string
	flagExtens                    []base.CombinedSliceFlagValue
	flagAdditionalValidPrincipals []base.CombinedSliceFlagValue
}

func extraVaultSshCertificateActionsFlagsMapFuncImpl() map[string][]string {
	flags := map[string][]string{
		"create": {
			pathFlagName,
			usernameName,
			keyTypeName,
			keyBitsName,
			ttlName,
			keyIdName,
			criticalOptionsName,
			piecewiseCriticalOptionsName,
			extensionsName,
			piecewiseExtensionName,
			additionalValidPrincipalsName,
		},
		"update": {
			pathFlagName,
			usernameName,
			keyTypeName,
			keyBitsName,
			ttlName,
			keyIdName,
			criticalOptionsName,
			piecewiseCriticalOptionsName,
			extensionsName,
			piecewiseExtensionName,
			additionalValidPrincipalsName,
		},
	}
	return flags
}

func extraVaultSshCertificateFlagsFuncImpl(c *VaultSshCertificateCommand, set *base.FlagSets, _ *base.FlagSet) {
	f := set.NewFlagSet("Vault SSH Certificate Credential Library Options")

	for _, name := range flagsVaultSshCertificateMap[c.Func] {
		switch name {
		case pathFlagName:
			f.StringVar(&base.StringVar{
				Name:   pathFlagName,
				Target: &c.flagPath,
				Usage:  "The path in vault to request credentials from.",
			})
		case usernameName:
			f.StringVar(&base.StringVar{
				Name:   usernameName,
				Target: &c.flagUsername,
				Usage:  "The username to use with the ssh certificate.",
			})
		case keyTypeName:
			f.StringVar(&base.StringVar{
				Name:   keyTypeName,
				Target: &c.flagKeyType,
				Usage:  "The key type for the generated ssh private key. One of: ed25519, ecdsa, rsa.",
			})
		case keyBitsName:
			f.StringVar(&base.StringVar{
				Name:   keyBitsName,
				Target: &c.flagKeyBits,
				Usage:  "The number of bits when generating the ssh private key. Depends on key_type. If ed25519 this should not be set, or set to 0, if ecdsa one of 256, 384, 521, if rsa one of 2048, 3072, 4096.",
			})
		case ttlName:
			f.StringVar(&base.StringVar{
				Name:   ttlName,
				Target: &c.flagTtl,
				Usage:  "The time-to-live for the generated certificate.",
			})
		case keyIdName:
			f.StringVar(&base.StringVar{
				Name:   keyIdName,
				Target: &c.flagKeyId,
				Usage:  "The key id that the created certificate should have.",
			})
		case additionalValidPrincipalsName:
			f.CombinationSliceVar(&base.CombinationSliceVar{
				Name:   additionalValidPrincipalsName,
				Target: &c.flagAdditionalValidPrincipals,
				Usage:  "Principals to be signed as \"valid_principles\" in addition to username.",
			})
		}
	}
	criticalOptsInput := common.CombinedSliceFlagValuePopulationInput{
		FlagSet:                          f,
		FlagNames:                        flagsVaultSshCertificateMap[c.Func],
		FullPopulationFlag:               &c.flagCriticalOptions,
		FullPopulationInputName:          criticalOptionsName,
		PiecewisePopulationFlag:          &c.flagCriticalOpts,
		PiecewisePopulationInputBaseName: piecewiseCriticalOptionsName,
		PiecewiseNoProtoCompat:           true,
	}
	common.PopulateCombinedSliceFlagValue(criticalOptsInput)

	extensionsInput := common.CombinedSliceFlagValuePopulationInput{
		FlagSet:                          f,
		FlagNames:                        flagsVaultSshCertificateMap[c.Func],
		FullPopulationFlag:               &c.flagExtensions,
		FullPopulationInputName:          extensionsName,
		PiecewisePopulationFlag:          &c.flagExtens,
		PiecewisePopulationInputBaseName: piecewiseExtensionName,
		PiecewiseNoProtoCompat:           true,
	}
	common.PopulateCombinedSliceFlagValue(extensionsInput)
}

func extraVaultSshCertificateFlagHandlingFuncImpl(c *VaultSshCertificateCommand, _ *base.FlagSets, opts *[]credentiallibraries.Option) bool {
	switch c.flagPath {
	case "":
	default:
		*opts = append(*opts, credentiallibraries.WithVaultCredentialLibraryPath(c.flagPath))
	}
	switch c.flagUsername {
	case "":
	default:
		*opts = append(*opts, credentiallibraries.WithVaultSSHCertificateCredentialLibraryUsername(c.flagUsername))
	}
	switch c.flagKeyType {
	case "":
	case "null":
		*opts = append(*opts, credentiallibraries.DefaultVaultSSHCertificateCredentialLibraryKeyType())
	default:
		*opts = append(*opts, credentiallibraries.WithVaultSSHCertificateCredentialLibraryKeyType(c.flagKeyType))
	}
	switch c.flagKeyBits {
	case "":
	case "0", "null":
		*opts = append(*opts, credentiallibraries.DefaultVaultSSHCertificateCredentialLibraryKeyBits())
	default:
		var final uint32
		keyBits, err := strconv.ParseUint(c.flagKeyBits, 10, 32)
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error parsing %q: %s", c.flagKeyBits, err))
			return false
		}
		final = uint32(keyBits)
		*opts = append(*opts, credentiallibraries.WithVaultSSHCertificateCredentialLibraryKeyBits(final))
	}
	switch c.flagTtl {
	case "":
	case "null":
		*opts = append(*opts, credentiallibraries.DefaultVaultSSHCertificateCredentialLibraryTtl())
	default:
		*opts = append(*opts, credentiallibraries.WithVaultSSHCertificateCredentialLibraryTtl(c.flagTtl))
	}
	switch c.flagKeyId {
	case "":
	case "null":
		*opts = append(*opts, credentiallibraries.DefaultVaultSSHCertificateCredentialLibraryKeyId())
	default:
		*opts = append(*opts, credentiallibraries.WithVaultSSHCertificateCredentialLibraryKeyId(c.flagKeyId))
	}
	// the weird formatting of this switch is to determine if there was only 0 or 1 principals passed, and if that signifies using default (nil)
	switch len(c.flagAdditionalValidPrincipals) {
	case 0:
	case 1:
		if len(c.flagAdditionalValidPrincipals[0].Keys) == 1 && c.flagAdditionalValidPrincipals[0].Keys[0] == "null" && c.flagAdditionalValidPrincipals[0].Value == nil {
			*opts = append(*opts, credentiallibraries.DefaultVaultSSHCertificateCredentialLibraryAdditionalValidPrincipals())
			break
		}
		fallthrough
	default:
		avp := make([]string, len(c.flagAdditionalValidPrincipals))
		for i, p := range c.flagAdditionalValidPrincipals {
			avp[i] = p.Value.GetValue()
		}
		*opts = append(*opts, credentiallibraries.WithVaultSSHCertificateCredentialLibraryAdditionalValidPrincipals(avp))
	}

	if err := common.HandleAttributeFlags(
		c.Command,
		piecewiseCriticalOptionsName,
		c.flagCriticalOptions,
		c.flagCriticalOpts,
		func() {
			*opts = append(*opts, credentiallibraries.DefaultVaultSSHCertificateCredentialLibraryCriticalOptions())
		},
		func(in map[string]any) {
			inn := make(map[string]string, len(in))
			for k, v := range in {
				switch vv := v.(type) {
				case nil:
					inn[k] = ""
				case string:
					inn[k] = vv
				default:
					continue
				}
			}
			*opts = append(*opts, credentiallibraries.WithVaultSSHCertificateCredentialLibraryCriticalOptions(inn))
		}); err != nil {
		return false
	}
	if err := common.HandleAttributeFlags(
		c.Command,
		piecewiseExtensionName,
		c.flagExtensions,
		c.flagExtens,
		func() {
			*opts = append(*opts, credentiallibraries.DefaultVaultSSHCertificateCredentialLibraryExtensions())
		},
		func(in map[string]any) {
			inn := make(map[string]string, len(in))
			for k, v := range in {
				switch vv := v.(type) {
				case nil:
					inn[k] = ""
				case string:
					inn[k] = vv
				default:
					continue
				}
			}
			*opts = append(*opts, credentiallibraries.WithVaultSSHCertificateCredentialLibraryExtensions(inn))
		}); err != nil {
		return false
	}

	return true
}

func (c *VaultSshCertificateCommand) extraVaultSshCertificateHelpFunc(_ map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary credential-libraries create vault-ssh-certificate -credential-store-id [options] [args]",
			"",
			"  Create a vault-ssh-certificate-type credential library. Example:",
			"",
			`    $ boundary credential-libraries create vault-ssh-certificate -credential-store-id  csvlt_1234567890 -vault-path "/ssh/sign/role" -username user`,
			"",
			"",
		})

	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary credential-libraries update vault-ssh-certificate [options] [args]",
			"",
			"  Update a vault-ssh-certificate-type credential library given its ID. Example:",
			"",
			`    $ boundary credential-libraries update vault-ssh-certificate -id clvsclt_1234567890 -name devops -description "For DevOps usage"`,
			"",
			"",
		})
	}
	return helpStr + c.Flags().Help()
}
