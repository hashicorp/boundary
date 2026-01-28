// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package authmethodscmd

import (
	"fmt"
	"strconv"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func init() {
	extraOidcActionsFlagsMapFunc = extraOidcActionsFlagsMapFuncImpl
	extraOidcFlagsFunc = extraOidcFlagsFuncImpl
	extraOidcFlagsHandlingFunc = extraOidcFlagHandlingFuncImpl
	executeExtraOidcActions = executeExtraOidcActionsImpl
}

type extraOidcCmdVars struct {
	flagState                             string
	flagIssuer                            string
	flagClientId                          string
	flagClientSecret                      string
	flagMaxAgeSeconds                     string
	flagApiUrlPrefix                      string
	flagSigningAlgorithms                 []string
	flagIdpCaCerts                        []string
	flagAllowedAudiences                  []string
	flagClaimsScopes                      []string
	flagAccountClaimMaps                  []string
	flagDisableDiscoveredConfigValidation bool
	flagDryRun                            bool
	flagPrompts                           []string
}

const (
	idFlagName                                = "id"
	issuerFlagName                            = "issuer"
	clientIdFlagName                          = "client-id"
	clientSecretFlagName                      = "client-secret"
	maxAgeFlagName                            = "max-age"
	signingAlgorithmFlagName                  = "signing-algorithm"
	apiUrlPrefixFlagName                      = "api-url-prefix"
	caCertFlagName                            = "idp-ca-cert"
	allowedAudienceFlagName                   = "allowed-audience"
	claimsScopes                              = "claims-scopes"
	accountClaimMaps                          = "account-claim-maps"
	stateFlagName                             = "state"
	disableDiscoveredConfigValidationFlagName = "disable-discovered-config-validation"
	dryRunFlagName                            = "dry-run"
	promptsFlagName                           = "prompts"
)

func extraOidcActionsFlagsMapFuncImpl() map[string][]string {
	flags := map[string][]string{
		"create": {
			issuerFlagName,
			clientIdFlagName,
			clientSecretFlagName,
			maxAgeFlagName,
			signingAlgorithmFlagName,
			apiUrlPrefixFlagName,
			caCertFlagName,
			allowedAudienceFlagName,
			claimsScopes,
			accountClaimMaps,
			promptsFlagName,
		},
		"change-state": {
			idFlagName,
			stateFlagName,
			disableDiscoveredConfigValidationFlagName,
		},
	}
	flags["update"] = append(flags["create"], disableDiscoveredConfigValidationFlagName, dryRunFlagName)
	return flags
}

func extraOidcFlagsFuncImpl(c *OidcCommand, set *base.FlagSets, _ *base.FlagSet) {
	f := set.NewFlagSet("OIDC Auth Method Options")

	for _, name := range flagsOidcMap[c.Func] {
		switch name {
		case issuerFlagName:
			f.StringVar(&base.StringVar{
				Name:   issuerFlagName,
				Target: &c.flagIssuer,
				Usage:  "The provider's Issuer URL.",
			})
		case clientIdFlagName:
			f.StringVar(&base.StringVar{
				Name:   clientIdFlagName,
				Target: &c.flagClientId,
				Usage:  "The OAuth 2.0 Client Identifier this auth method should use with the provider.",
			})
		case clientSecretFlagName:
			f.StringVar(&base.StringVar{
				Name:   clientSecretFlagName,
				Target: &c.flagClientSecret,
				Usage:  "The corresponding client secret.",
			})
		case maxAgeFlagName:
			f.StringVar(&base.StringVar{
				Name:   maxAgeFlagName,
				Target: &c.flagMaxAgeSeconds,
				Usage:  `The OIDC "max_age" parameter sent to the provider.`,
			})
		case signingAlgorithmFlagName:
			f.StringSliceVar(&base.StringSliceVar{
				Name:   signingAlgorithmFlagName,
				Target: &c.flagSigningAlgorithms,
				Usage:  "The allowed signing algorithm. May be specified multiple times for multiple values.",
			})
		case apiUrlPrefixFlagName:
			f.StringVar(&base.StringVar{
				Name:   apiUrlPrefixFlagName,
				Target: &c.flagApiUrlPrefix,
				Usage:  "The URL prefix used by the OIDC provider in the authentication flow.",
			})
		case caCertFlagName:
			f.StringSliceVar(&base.StringSliceVar{
				Name:   caCertFlagName,
				Target: &c.flagIdpCaCerts,
				Usage:  "Optional PEM-encoded X.509 CA certificate that can be used as trust anchors when connecting to an OIDC provider. May be specified multiple times.",
			})
		case allowedAudienceFlagName:
			f.StringSliceVar(&base.StringSliceVar{
				Name:   allowedAudienceFlagName,
				Target: &c.flagAllowedAudiences,
				Usage:  `The acceptable audience ("aud") claim. May be specified multiple times.`,
			})
		case claimsScopes:
			f.StringSliceVar(&base.StringSliceVar{
				Name:   claimsScopes,
				Target: &c.flagClaimsScopes,
				Usage:  `The optional claims scope requested. May be specified multiple times.`,
			})
		case accountClaimMaps:
			f.StringSliceVar(&base.StringSliceVar{
				Name:   accountClaimMaps,
				Target: &c.flagAccountClaimMaps,
				Usage:  `The optional account claim maps from custom claims to the standard claims of sub, name and email.  These maps are represented as key=value where the key equals the Provider from-claim and the value equals the Boundary to-claim.  For example "oid=sub". May be specified multiple times for different to-claims.`,
			})
		case stateFlagName:
			f.StringVar(&base.StringVar{
				Name:   stateFlagName,
				Target: &c.flagState,
				Usage:  "The desired operational state of the auth method.",
			})
		case disableDiscoveredConfigValidationFlagName:
			f.BoolVar(&base.BoolVar{
				Name:   disableDiscoveredConfigValidationFlagName,
				Target: &c.flagDisableDiscoveredConfigValidation,
				Usage:  "Disable validating the given auth method against configuration from the authorization server's discovery URL. This must be specified every time an unvalidatable auth method is updated or state changed; not specifying it is equivalent to setting it to false.",
			})
		case dryRunFlagName:
			f.BoolVar(&base.BoolVar{
				Name:   dryRunFlagName,
				Target: &c.flagDryRun,
				Usage:  "Performs all completeness and validation checks with any newly-provided values without persisting the changes.",
			})
		case promptsFlagName:
			f.StringSliceVar(&base.StringSliceVar{
				Name:   promptsFlagName,
				Target: &c.flagPrompts,
				Usage:  "The optional prompt parameter that can be included in the authentication request to control the behavior of the authentication flow.",
			})
		}
	}
}

func (c *OidcCommand) extraOidcHelpFunc(helpMap map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary auth-methods create oidc [options] [args]",
			"",
			"  Create an oidc-type auth method. Example:",
			"",
			`    $ boundary auth-methods create oidc -name prodops -description "Oidc auth-method for ProdOps"`,
			"",
			"",
		})

	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary auth-methods update oidc [options] [args]",
			"",
			"  Update an oidc-type auth method given its ID. Example:",
			"",
			`    $ boundary auth-methods update oidc -id amoidc_1234567890 -name "devops" -description "Oidc auth-method for DevOps"`,
			"",
			"",
		})
	case "change-state":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary auth-methods change-state oidc [options] [args]",
			"",
			"  Change the active and visibility state of an oidc-type auth method given its ID. Example:",
			"",
			`    $ boundary auth-methods change-state oidc -id amoidc_1234567890 -state "public-active"`,
			"",
			"",
		})
	}
	return helpStr + c.Flags().Help()
}

func extraOidcFlagHandlingFuncImpl(c *OidcCommand, f *base.FlagSets, opts *[]authmethods.Option) bool {
	switch c.flagIssuer {
	case "":
	case "null":
		*opts = append(*opts, authmethods.DefaultOidcAuthMethodIssuer())
	default:
		*opts = append(*opts, authmethods.WithOidcAuthMethodIssuer(c.flagIssuer))
	}
	switch c.flagClientId {
	case "":
	case "null":
		*opts = append(*opts, authmethods.DefaultOidcAuthMethodClientId())
	default:
		*opts = append(*opts, authmethods.WithOidcAuthMethodClientId(c.flagClientId))
	}
	switch c.flagClientSecret {
	case "":
	case "null":
		*opts = append(*opts, authmethods.DefaultOidcAuthMethodClientSecret())
	default:
		*opts = append(*opts, authmethods.WithOidcAuthMethodClientSecret(c.flagClientSecret))
	}
	switch c.flagMaxAgeSeconds {
	case "":
	case "null":
		*opts = append(*opts, authmethods.DefaultOidcAuthMethodMaxAge())
	default:
		val, err := strconv.ParseUint(c.flagMaxAgeSeconds, 10, 32)
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error parsing %q: %s", c.flagMaxAgeSeconds, err))
			return false
		}
		*opts = append(*opts, authmethods.WithOidcAuthMethodMaxAge(uint32(val)))
	}
	switch c.flagApiUrlPrefix {
	case "":
	case "null":
		*opts = append(*opts, authmethods.DefaultOidcAuthMethodApiUrlPrefix())
	default:
		*opts = append(*opts, authmethods.WithOidcAuthMethodApiUrlPrefix(c.flagApiUrlPrefix))
	}
	switch {
	case len(c.flagSigningAlgorithms) == 0:
	case len(c.flagSigningAlgorithms) == 1 && c.flagSigningAlgorithms[0] == "null":
		*opts = append(*opts, authmethods.DefaultOidcAuthMethodSigningAlgorithms())
	default:
		*opts = append(*opts, authmethods.WithOidcAuthMethodSigningAlgorithms(c.flagSigningAlgorithms))
	}
	switch {
	case len(c.flagIdpCaCerts) == 0:
	case len(c.flagIdpCaCerts) == 1 && c.flagIdpCaCerts[0] == "null":
		*opts = append(*opts, authmethods.DefaultOidcAuthMethodIdpCaCerts())
	default:
		*opts = append(*opts, authmethods.WithOidcAuthMethodIdpCaCerts(c.flagIdpCaCerts))
	}
	switch {
	case len(c.flagAllowedAudiences) == 0:
	case len(c.flagAllowedAudiences) == 1 && c.flagAllowedAudiences[0] == "null":
		*opts = append(*opts, authmethods.DefaultOidcAuthMethodAllowedAudiences())
	default:
		*opts = append(*opts, authmethods.WithOidcAuthMethodAllowedAudiences(c.flagAllowedAudiences))
	}
	switch {
	case len(c.flagClaimsScopes) == 0:
	case len(c.flagClaimsScopes) == 1 && c.flagClaimsScopes[0] == "null":
		*opts = append(*opts, authmethods.DefaultOidcAuthMethodClaimsScopes())
	default:
		*opts = append(*opts, authmethods.WithOidcAuthMethodClaimsScopes(c.flagClaimsScopes))
	}
	switch {
	case len(c.flagAccountClaimMaps) == 0:
	case len(c.flagAccountClaimMaps) == 1 && c.flagAccountClaimMaps[0] == "null":
		*opts = append(*opts, authmethods.DefaultOidcAuthMethodAccountClaimMaps())
	default:
		*opts = append(*opts, authmethods.WithOidcAuthMethodAccountClaimMaps(c.flagAccountClaimMaps))
	}
	if c.flagDisableDiscoveredConfigValidation {
		*opts = append(*opts, authmethods.WithOidcAuthMethodDisableDiscoveredConfigValidation(c.flagDisableDiscoveredConfigValidation))
	}
	if c.flagDryRun {
		*opts = append(*opts, authmethods.WithOidcAuthMethodDryRun(c.flagDryRun))
	}
	switch {
	case len(c.flagPrompts) == 0:
	case len(c.flagPrompts) == 1 && c.flagPrompts[0] == "null":
		*opts = append(*opts, authmethods.DefaultOidcAuthMethodPrompts())
	default:
		*opts = append(*opts, authmethods.WithOidcAuthMethodPrompts(c.flagPrompts))
	}

	return true
}

func executeExtraOidcActionsImpl(c *OidcCommand, origResp *api.Response, origItem *authmethods.AuthMethod, origError error, amClient *authmethods.Client, version uint32, opts []authmethods.Option) (*api.Response, *authmethods.AuthMethod, error) {
	switch c.Func {
	case "change-state":
		if c.flagDisableDiscoveredConfigValidation {
			opts = append(opts, authmethods.WithOidcAuthMethodDisableDiscoveredConfigValidation(true))
		}
		result, err := amClient.ChangeState(c.Context, c.FlagId, version, c.flagState, opts...)
		if err != nil {
			return nil, nil, err
		}
		return result.GetResponse(), result.GetItem(), nil
	}
	return origResp, origItem, origError
}
