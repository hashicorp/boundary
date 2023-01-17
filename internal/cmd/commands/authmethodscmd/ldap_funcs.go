package authmethodscmd

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"

	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func init() {
	extraLdapActionsFlagsMapFunc = extraLdapActionsFlagsMapFuncImpl
	extraLdapFlagsFunc = extraLdapFlagsFuncImpl
	extraLdapFlagsHandlingFunc = extraLdapFlagHandlingFuncImpl
}

type extraLdapCmdVars struct {
	flagUrls                 []string
	flagInsecureTls          bool
	flagDiscoverDn           bool
	flagAnonGroupSearch      bool
	flagUpnDomain            string
	flagStartTls             bool
	flagUserDn               string
	flagUserAttr             string
	flagUserFilter           string
	flagEnableGroups         bool
	flagGroupDn              string
	flagGroupAttr            string
	flagGroupFilter          string
	flagCertificates         []string
	flagClientCertificate    string
	flagClientCertificateKey string
	flagBindDn               string
	flagBindPassword         string
	flagUseTokenGroups       bool
	flagAccountAttributeMaps []string
}

const (
	urlsFlagName                 = "urls"
	insecureTlsFlagName          = "insecure-tls"
	discoverDnFlagName           = "discover-dn"
	anonGroupSearchFlagName      = "anon-group-search"
	upnDomainFlagName            = "upn-domain"
	startTlsFlagName             = "start-tls"
	userDnFlagName               = "user-dn"
	userAttrFlagName             = "user-attr"
	userFilterFlagName           = "user-filter"
	enableGroupsFlagName         = "enable-groups"
	groupDnFlagName              = "group-dn"
	groupAttrFlagName            = "group-attr"
	groupFilterFlagName          = "group-filter"
	certificatesFlagName         = "certificate"
	clientCertificateFlagName    = "client-certificate"
	clientCertificateKeyFlagName = "client-certificate-key"
	bindDnFlagName               = "bind-dn"
	bindPasswordFlagName         = "bind-password"
	useTokenGroupsFlagName       = "use-token-groups"
	accountAttributeMaps         = "account-attribute-map"
)

func extraLdapActionsFlagsMapFuncImpl() map[string][]string {
	flags := map[string][]string{
		"create": {
			urlsFlagName,
			insecureTlsFlagName,
			discoverDnFlagName,
			anonGroupSearchFlagName,
			upnDomainFlagName,
			startTlsFlagName,
			userDnFlagName,
			userAttrFlagName,
			userFilterFlagName,
			enableGroupsFlagName,
			groupDnFlagName,
			groupAttrFlagName,
			groupFilterFlagName,
			certificatesFlagName,
			clientCertificateFlagName,
			clientCertificateKeyFlagName,
			bindDnFlagName,
			bindPasswordFlagName,
			useTokenGroupsFlagName,
			accountAttributeMaps,
		},
	}
	flags["update"] = flags["create"]
	return flags
}

func extraLdapFlagsFuncImpl(c *LdapCommand, set *base.FlagSets, _ *base.FlagSet) {
	f := set.NewFlagSet("LDAP Auth Method Options")

	for _, name := range flagsLdapMap[c.Func] {
		switch name {
		case urlsFlagName:
			f.StringSliceVar(&base.StringSliceVar{
				Name:   urlsFlagName,
				Target: &c.flagUrls,
				Usage:  "The LDAP URLs that specify LDAP servers to connect to (required).  May be specified multiple times.",
			})
		case startTlsFlagName:
			f.BoolVar(&base.BoolVar{
				Name:   startTlsFlagName,
				Target: &c.flagStartTls,
				Usage:  "Issue StartTLS command after connecting (optional).",
			})
		case insecureTlsFlagName:
			f.BoolVar(&base.BoolVar{
				Name:   insecureTlsFlagName,
				Target: &c.flagInsecureTls,
				Usage:  "Skip the LDAP server SSL certificate validation (optional) - insecure and use with caution.",
			})
		case discoverDnFlagName:
			f.BoolVar(&base.BoolVar{
				Name:   discoverDnFlagName,
				Target: &c.flagDiscoverDn,
				Usage:  "Use anon bind to discover the bind DN of a user (optional).",
			})
		case anonGroupSearchFlagName:
			f.BoolVar(&base.BoolVar{
				Name:   anonGroupSearchFlagName,
				Target: &c.flagAnonGroupSearch,
				Usage:  "Use anon bind when performing LDAP group searches (optional).",
			})
		case upnDomainFlagName:
			f.StringVar(&base.StringVar{
				Name:   upnDomainFlagName,
				Target: &c.flagUpnDomain,
				Usage:  "The userPrincipalDomain used to construct the UPN string for the authenticating user (optional).",
			})
		case userDnFlagName:
			f.StringVar(&base.StringVar{
				Name:   userDnFlagName,
				Target: &c.flagUserDn,
				Usage:  "The base DN under which to perform user search (optional).",
			})
		case userAttrFlagName:
			f.StringVar(&base.StringVar{
				Name:   userAttrFlagName,
				Target: &c.flagUserAttr,
				Usage:  "The attribute on user entry matching the username passed when authenticating (optional).",
			})
		case userFilterFlagName:
			f.StringVar(&base.StringVar{
				Name:   userFilterFlagName,
				Target: &c.flagUserFilter,
				Usage:  "A go template used to construct a LDAP user search filter (optional).",
			})
		case enableGroupsFlagName:
			f.BoolVar(&base.BoolVar{
				Name:   enableGroupsFlagName,
				Target: &c.flagEnableGroups,
				Usage:  "Find the authenticated user's groups during authentication (optional).",
			})
		case groupDnFlagName:
			f.StringVar(&base.StringVar{
				Name:   groupDnFlagName,
				Target: &c.flagGroupDn,
				Usage:  "The base DN under which to perform group search.",
			})
		case groupAttrFlagName:
			f.StringVar(&base.StringVar{
				Name:   groupAttrFlagName,
				Target: &c.flagGroupAttr,
				Usage:  "The attribute that enumerates a user's group membership from entries returned by a group search (optional).",
			})
		case groupFilterFlagName:
			f.StringVar(&base.StringVar{
				Name:   groupFilterFlagName,
				Target: &c.flagGroupFilter,
				Usage:  "A go template used to construct a LDAP group search filter (optional).",
			})
		case certificatesFlagName:
			f.StringSliceVar(&base.StringSliceVar{
				Name:   certificatesFlagName,
				Target: &c.flagCertificates,
				Usage:  "PEM-encoded X.509 CA certificate that can be used as trust anchors when connecting to an LDAP server (optional). May be specified multiple times.",
			})
		case clientCertificateFlagName:
			f.StringVar(&base.StringVar{
				Name:   clientCertificateFlagName,
				Target: &c.flagClientCertificate,
				Usage:  "A client certificate in ASN.1 DER form encoded as PEM (optional).",
			})
		case clientCertificateKeyFlagName:
			f.StringVar(&base.StringVar{
				Name:   clientCertificateKeyFlagName,
				Target: &c.flagClientCertificateKey,
				Usage:  "A client certificate key in PKCS #8, ASN.1 DER form encoded as PEM (optional).",
			})
		case bindDnFlagName:
			f.StringVar(&base.StringVar{
				Name:   bindDnFlagName,
				Target: &c.flagBindDn,
				Usage:  "The distinguished name of entry to bind when performing user and group searches (optional).",
			})
		case bindPasswordFlagName:
			f.StringVar(&base.StringVar{
				Name:   bindPasswordFlagName,
				Target: &c.flagBindPassword,
				Usage:  "The password to use along with bind-dn performing user and group searches (optional).",
			})
		case useTokenGroupsFlagName:
			f.BoolVar(&base.BoolVar{
				Name:   useTokenGroupsFlagName,
				Target: &c.flagUseTokenGroups,
				Usage:  "Use the Active Directory tokenGroups constructed attribute of the user to find the group memberships (optional).",
			})
		}
	}
}

func (c *LdapCommand) extraLdapHelpFunc(helpMap map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary auth-methods create ldap [options] [args]",
			"",
			"  Create an ldap-type auth method. Example:",
			"",
			`    $ boundary auth-methods create ldap -name prodops -description "LDAP auth-method for ProdOps"`,
			"",
			"",
		})

	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary auth-methods update ldap [options] [args]",
			"",
			"  Update an ldap-type auth method given its ID. Example:",
			"",
			`    $ boundary auth-methods update ldap -id amldap_1234567890 -name "devops" -description "LDAP auth-method for DevOps"`,
			"",
			"",
		})
	}
	return helpStr + c.Flags().Help()
}

func extraLdapFlagHandlingFuncImpl(c *LdapCommand, _ *base.FlagSets, opts *[]authmethods.Option) bool {
	switch {
	case len(c.flagUrls) == 0:
	case len(c.flagUrls) == 1 && c.flagUrls[0] == "null":
		c.UI.Error(fmt.Sprintf("There must be at least one %q", urlsFlagName))
		return false
	default:
		for _, urlString := range c.flagUrls {
			u, err := url.Parse(urlString)
			if err != nil {
				c.UI.Error(fmt.Sprintf("Error parsing URL %q: %s", urlString, err))
				return false
			}
			switch u.Scheme {
			case "ldap", "ldaps":
			default:
				c.UI.Error(fmt.Sprintf("scheme in url %q is not either ldap or ldaps", urlString))
				return false
			}
		}
		*opts = append(*opts, authmethods.WithLdapAuthMethodUrls(c.flagUrls))
	}

	switch c.flagStartTls {
	case true:
		*opts = append(*opts, authmethods.WithLdapAuthMethodStartTls(true))
	default:
		*opts = append(*opts, authmethods.WithLdapAuthMethodStartTls(false))
	}

	switch c.flagInsecureTls {
	case true:
		*opts = append(*opts, authmethods.WithLdapAuthMethodInsecureTls(true))
	default:
		*opts = append(*opts, authmethods.WithLdapAuthMethodInsecureTls(false))
	}

	switch c.flagDiscoverDn {
	case true:
		*opts = append(*opts, authmethods.WithLdapAuthMethodDiscoverDn(true))
	default:
		*opts = append(*opts, authmethods.WithLdapAuthMethodDiscoverDn(false))
	}

	switch c.flagAnonGroupSearch {
	case true:
		*opts = append(*opts, authmethods.WithLdapAuthMethodAnonGroupSearch(true))
	default:
		*opts = append(*opts, authmethods.WithLdapAuthMethodAnonGroupSearch(false))
	}

	switch c.flagUpnDomain {
	case "":
	case "null":
		*opts = append(*opts, authmethods.DefaultLdapAuthMethodUpnDomain())
	default:
		*opts = append(*opts, authmethods.WithLdapAuthMethodUpnDomain(c.flagUpnDomain))
	}

	switch c.flagUserDn {
	case "":
	case "null":
		*opts = append(*opts, authmethods.DefaultLdapAuthMethodUserDn())
	default:
		*opts = append(*opts, authmethods.WithLdapAuthMethodUserDn(c.flagUserDn))
	}

	switch c.flagUserAttr {
	case "":
	case "null":
		*opts = append(*opts, authmethods.DefaultLdapAuthMethodUserAttr())
	default:
		*opts = append(*opts, authmethods.WithLdapAuthMethodUserAttr(c.flagUserAttr))
	}

	switch c.flagUserFilter {
	case "":
	case "null":
		*opts = append(*opts, authmethods.DefaultLdapAuthMethodUserFilter())
	default:
		*opts = append(*opts, authmethods.WithLdapAuthMethodUserFilter(c.flagUserFilter))
	}

	switch c.flagEnableGroups {
	case true:
		*opts = append(*opts, authmethods.WithLdapAuthMethodEnableGroups(true))
	default:
		*opts = append(*opts, authmethods.WithLdapAuthMethodEnableGroups(false))
	}

	switch c.flagGroupDn {
	case "":
	case "null":
		*opts = append(*opts, authmethods.DefaultLdapAuthMethodGroupDn())
	default:
		*opts = append(*opts, authmethods.WithLdapAuthMethodGroupDn(c.flagGroupDn))
	}

	switch c.flagGroupAttr {
	case "":
	case "null":
		*opts = append(*opts, authmethods.DefaultLdapAuthMethodGroupAttr())
	default:
		*opts = append(*opts, authmethods.WithLdapAuthMethodGroupAttr(c.flagGroupAttr))
	}

	switch c.flagGroupFilter {
	case "":
	case "null":
		*opts = append(*opts, authmethods.DefaultLdapAuthMethodGroupFilter())
	default:
		*opts = append(*opts, authmethods.WithLdapAuthMethodGroupFilter(c.flagGroupFilter))
	}

	switch {
	case len(c.flagCertificates) == 0:
	case len(c.flagCertificates) == 1 && c.flagCertificates[0] == "null":
		*opts = append(*opts, authmethods.DefaultLdapAuthMethodCertificates())
	default:
		if err := validateCerts(c.flagCertificates...); err != nil {
			c.UI.Error(fmt.Sprintf("invalid certificate: %s", err.Error()))
			return false
		}
		*opts = append(*opts, authmethods.WithLdapAuthMethodCertificates(c.flagCertificates))
	}

	switch c.flagClientCertificate {
	case "":
	case "null":
		*opts = append(*opts, authmethods.DefaultLdapAuthMethodClientCertificate())
	default:
		*opts = append(*opts, authmethods.WithLdapAuthMethodClientCertificate(c.flagClientCertificate))
	}

	switch c.flagClientCertificateKey {
	case "":
	case "null":
		*opts = append(*opts, authmethods.DefaultLdapAuthMethodClientCertificateKey())
	default:
		*opts = append(*opts, authmethods.WithLdapAuthMethodClientCertificateKey(c.flagClientCertificateKey))
	}

	switch c.flagBindDn {
	case "":
	case "null":
		*opts = append(*opts, authmethods.DefaultLdapAuthMethodBindDn())
	default:
		*opts = append(*opts, authmethods.WithLdapAuthMethodBindDn(c.flagBindDn))
	}

	switch c.flagBindPassword {
	case "":
	case "null":
		*opts = append(*opts, authmethods.DefaultLdapAuthMethodBindPassword())
	default:
		*opts = append(*opts, authmethods.WithLdapAuthMethodBindPassword(c.flagBindPassword))
	}

	switch c.flagUseTokenGroups {
	case true:
		*opts = append(*opts, authmethods.WithLdapAuthMethodUseTokenGroups(true))
	default:
		*opts = append(*opts, authmethods.WithLdapAuthMethodUseTokenGroups(false))
	}

	switch {
	case len(c.flagAccountAttributeMaps) == 0:
	case len(c.flagAccountAttributeMaps) == 1 && c.flagAccountAttributeMaps[0] == "null":
		*opts = append(*opts, authmethods.DefaultLdapAuthMethodAccountAttributeMaps())
	default:
		*opts = append(*opts, authmethods.WithLdapAuthMethodAccountAttributeMaps(c.flagAccountAttributeMaps))
	}

	return true
}

func validateCerts(pems ...string) error {
	if len(pems) == 0 {
		return errors.New("no PEMs provided")
	}
	for _, p := range pems {
		if p == "" {
			return errors.New("empty certificate PEM")
		}
		block, _ := pem.Decode([]byte(p))
		if block == nil {
			return errors.New("failed to parse certificate: invalid PEM encoding")
		}
		_, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse certificate: invalid block: %w", err)
		}
	}
	return nil
}
