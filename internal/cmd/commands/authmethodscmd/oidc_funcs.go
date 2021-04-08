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
	flagCaCerts                           []string
	flagAllowedAudiences                  []string
	flagDisableDiscoveredConfigValidation bool
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
	stateFlagName                             = "state"
	disableDiscoveredConfigValidationFlagName = "disable-discovered-config-validation"
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
		},
		"change-state": {
			idFlagName,
			stateFlagName,
			disableDiscoveredConfigValidationFlagName,
		},
	}
	flags["update"] = append(flags["create"], disableDiscoveredConfigValidationFlagName)
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
				Target: &c.flagCaCerts,
				Usage:  "Optional PEM-encoded X.509 CA certificate that can be used as trust anchors when connecting to an OIDC provider. May be specified multiple times.",
			})
		case allowedAudienceFlagName:
			f.StringSliceVar(&base.StringSliceVar{
				Name:   allowedAudienceFlagName,
				Target: &c.flagAllowedAudiences,
				Usage:  `The acceptable audience ("aud") claim. May be specified multiple times.`,
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
				Usage:  "Disable validating the given parameters against configuration from the authorization server's discovery URL. This must be specified every time there is an update or state change; not specifying it is equivalent to setting it to false.",
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
	switch c.flagSigningAlgorithms {
	case nil:
		*opts = append(*opts, authmethods.DefaultOidcAuthMethodSigningAlgorithms())
	default:
		*opts = append(*opts, authmethods.WithOidcAuthMethodSigningAlgorithms(c.flagSigningAlgorithms))
	}
	switch c.flagApiUrlPrefix {
	case "":
	case "null":
		*opts = append(*opts, authmethods.DefaultOidcAuthMethodApiUrlPrefix())
	default:
		*opts = append(*opts, authmethods.WithOidcAuthMethodApiUrlPrefix(c.flagApiUrlPrefix))
	}
	switch c.flagCaCerts {
	case nil:
		*opts = append(*opts, authmethods.DefaultOidcAuthMethodIdpCaCerts())
	default:
		*opts = append(*opts, authmethods.WithOidcAuthMethodIdpCaCerts(c.flagCaCerts))
	}
	switch c.flagAllowedAudiences {
	case nil:
		*opts = append(*opts, authmethods.DefaultOidcAuthMethodAllowedAudiences())
	default:
		*opts = append(*opts, authmethods.WithOidcAuthMethodAllowedAudiences(c.flagAllowedAudiences))
	}
	if c.flagDisableDiscoveredConfigValidation {
		*opts = append(*opts, authmethods.WithOidcAuthMethodDisableDiscoveredConfigValidation(c.flagDisableDiscoveredConfigValidation))
	}

	return true
}

func executeExtraOidcActionsImpl(c *OidcCommand, origResult api.GenericResult, origError error, amClient *authmethods.Client, version uint32, opts []authmethods.Option) (api.GenericResult, error) {
	switch c.Func {
	case "change-state":
		return amClient.ChangeState(c.Context, c.FlagId, version, c.flagState, opts...)
	}
	return origResult, origError
}
