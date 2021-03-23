package authmethodscmd

import (
	"fmt"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func init() {
	extraOidcActionsFlagsMapFunc = extraOidcActionsFlagsMapFuncImpl
	extraOidcFlagsFunc = extraOidcFlagsFuncImpl
	extraOidcFlagsHandlingFunc = extraOidcFlagHandlingFuncImpl
	executeExtraActions = executeExtraActionsImpl
}

type extraOidcCmdVars struct {
	flagState                   string
	flagDiscoveryUrl            string
	flagClientId                string
	flagClientSecret            string
	flagMaxAgeSeconds           int
	flagApiUrlPrefix            string
	flagSigningAlgorithms       []string
	flagCertificates            []string
	flagAllowedAudiences        []string
	flagOverrideDiscoveryConfig bool
}

const (
	discoveryFlagName        = "discovery-url"
	clientIdFlagName         = "client-id"
	clientSecretFlagName     = "client-secret"
	maxAgeFlagName           = "max-age"
	apiUrlPrefixFlagName     = "api-url-prefix"
	signingAlgorithmFlagName = "signing-algorithm"
	certificatesFlagName     = "certificates"
	audiencesFlagName        = "allowed-audiences"
	stateFlagName            = "state"
)

func extraOidcActionsFlagsMapFuncImpl() map[string][]string {
	flags := map[string][]string{
		"create": {
			discoveryFlagName,
			clientIdFlagName,
			clientSecretFlagName,
			maxAgeFlagName,
			apiUrlPrefixFlagName,
			signingAlgorithmFlagName,
			certificatesFlagName,
			audiencesFlagName,
		},
		"change-state": {
			stateFlagName,
		},
	}
	flags["update"] = flags["create"]
	return flags
}

func extraOidcFlagsFuncImpl(c *OidcCommand, set *base.FlagSets, f *base.FlagSet) {
	f = set.NewFlagSet("Oidc Auth Method Options")

	for _, name := range flagsOidcMap[c.Func] {
		switch name {
		case discoveryFlagName:
			f.StringVar(&base.StringVar{
				Name:   discoveryFlagName,
				Target: &c.flagDiscoveryUrl,
				Usage:  "The url to the provider's discovery config.",
			})
		case clientIdFlagName:
			f.StringVar(&base.StringVar{
				Name:   clientIdFlagName,
				Target: &c.flagClientId,
				Usage:  "An OAuth 2.0 Client Identifier valid at the Authorization Server.",
			})
		case clientSecretFlagName:
			f.StringVar(&base.StringVar{
				Name:   clientSecretFlagName,
				Target: &c.flagClientSecret,
				Usage:  "The client secret.",
			})
		case maxAgeFlagName:
			f.IntVar(&base.IntVar{
				Name:   maxAgeFlagName,
				Target: &c.flagMaxAgeSeconds,
				Usage:  "The elapsed time in seconds before the end user should be forced to re-authenticate.",
			})
		case apiUrlPrefixFlagName:
			f.StringVar(&base.StringVar{
				Name:   apiUrlPrefixFlagName,
				Target: &c.flagApiUrlPrefix,
				Usage:  "The url prefixes used by the OIDC provider in the authentication flow.",
			})
		case signingAlgorithmFlagName:
			f.StringSliceVar(&base.StringSliceVar{
				Name:   signingAlgorithmFlagName,
				Target: &c.flagSigningAlgorithms,
				Usage:  "The signing algorithms allowed for an oidc auth method.",
			})
		case certificatesFlagName:
			f.StringSliceVar(&base.StringSliceVar{
				Name:   certificatesFlagName,
				Target: &c.flagCertificates,
				Usage:  "Optional PEM encoded x509 certificates that can be used as trust anchors when connecting to an OIDC provider.",
			})
		case audiencesFlagName:
			f.StringSliceVar(&base.StringSliceVar{
				Name:   audiencesFlagName,
				Target: &c.flagAllowedAudiences,
				Usage:  "The audience claims for this auth method.",
			})
		case stateFlagName:
			f.StringVar(&base.StringVar{
				Name:   stateFlagName,
				Target: &c.flagState,
				Usage:  "The operational state of the auth method.",
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

func extraOidcFlagHandlingFuncImpl(c *OidcCommand, opts *[]authmethods.Option) bool {
	switch c.flagDiscoveryUrl {
	case "":
	case "null":
		*opts = append(*opts, authmethods.DefaultOidcAuthMethodDiscoveryUrl())
	default:
		*opts = append(*opts, authmethods.WithOidcAuthMethodDiscoveryUrl(c.flagDiscoveryUrl))
	}
	switch c.flagClientSecret {
	case "":
	case "null":
		*opts = append(*opts, authmethods.DefaultOidcAuthMethodClientSecret())
	default:
		*opts = append(*opts, authmethods.WithOidcAuthMethodClientSecret(c.flagClientSecret))
	}
	switch c.flagClientId {
	case "":
	case "null":
		*opts = append(*opts, authmethods.DefaultOidcAuthMethodClientId())
	default:
		*opts = append(*opts, authmethods.WithOidcAuthMethodClientId(c.flagClientId))
	}
	switch c.flagMaxAgeSeconds {
	// TODO: Figure out the right data type for this flag.
	case 0:
		c.UI.Error(fmt.Sprintf("Error parsing %q: %s"))
		return false
	default:
		*opts = append(*opts, authmethods.WithOidcAuthMethodMaxAge(int32(c.flagMaxAgeSeconds)))
	}
	switch c.flagApiUrlPrefix {
	case "":
	case "null":
		*opts = append(*opts, authmethods.DefaultOidcAuthMethodCallbackUrlPrefixes())
	default:
		*opts = append(*opts, authmethods.WithOidcAuthMethodCallbackUrlPrefixes([]string{c.flagApiUrlPrefix}))
	}
	switch c.flagSigningAlgorithms {
	case nil:
		*opts = append(*opts, authmethods.DefaultOidcAuthMethodSigningAlgorithms())
	default:
		*opts = append(*opts, authmethods.WithOidcAuthMethodSigningAlgorithms(c.flagSigningAlgorithms))
	}
	switch c.flagCertificates {
	case nil:
		*opts = append(*opts, authmethods.DefaultOidcAuthMethodCertificates())
	default:
		*opts = append(*opts, authmethods.WithOidcAuthMethodCertificates(c.flagCertificates))
	}
	switch c.flagAllowedAudiences {
	case nil:
		*opts = append(*opts, authmethods.DefaultOidcAuthMethodAllowedAudiences())
	default:
		*opts = append(*opts, authmethods.WithOidcAuthMethodAllowedAudiences(c.flagAllowedAudiences))
	}

	return true
}

func executeExtraActionsImpl(c *Command, origResult api.GenericResult, origError error, amClient *authmethods.Client, version uint32, opts []authmethods.Option) (api.GenericResult, error) {
	switch c.Func {
	case "change-state":
		return amClient.ChangeState(c.Context, c.FlagId, version, c.flagState, opts...)
	}
	return origResult, origError
}
