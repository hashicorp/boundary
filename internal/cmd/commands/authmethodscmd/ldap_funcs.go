// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package authmethodscmd

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/internal/auth/ldap"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
)

func init() {
	extraLdapActionsFlagsMapFunc = extraLdapActionsFlagsMapFuncImpl
	extraLdapFlagsFunc = extraLdapFlagsFuncImpl
	extraLdapFlagsHandlingFunc = extraLdapFlagHandlingFuncImpl
}

type extraLdapCmdVars struct {
	flagState                string
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
	flagMaxPageSize          uint64
	flagDerefAliases         string
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
	accountAttributeMapsFlagName = "account-attribute-map"
	maxPageSizeFlagName          = "max-page-size"
	derefAliasesFlagName         = "deref-aliases"
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
			accountAttributeMapsFlagName,
			stateFlagName,
			maxPageSizeFlagName,
			derefAliasesFlagName,
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
				Usage:  "PEM-encoded X.509 CA certificate in ASN.1 DER form that can be used as a trust anchor when connecting to an LDAP server(optional).  This may be specified multiple times",
			})
		case clientCertificateFlagName:
			f.StringVar(&base.StringVar{
				Name:   clientCertificateFlagName,
				Target: &c.flagClientCertificate,
				Usage:  "PEM-encoded X.509 client certificate in ASN.1 DER form that can be used to authenticate against an LDAP server(optional).",
			})
		case clientCertificateKeyFlagName:
			f.StringVar(&base.StringVar{
				Name:   clientCertificateKeyFlagName,
				Target: &c.flagClientCertificateKey,
				Usage:  "PEM-encoded X.509 client certificate key in PKCS #8, ASN.1 DER form used with the client certificate (optional).",
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
		case stateFlagName:
			f.StringVar(&base.StringVar{
				Name:   stateFlagName,
				Target: &c.flagState,
				Usage:  "The desired operational state of the auth method.",
			})
		case maxPageSizeFlagName:
			f.Uint64Var(&base.Uint64Var{
				Name:   maxPageSizeFlagName,
				Target: &c.flagMaxPageSize,
				Usage:  "MaximumPageSize specifies a maximum search result size to use when retrieving the authenticated user's groups (optional).",
			})
		case derefAliasesFlagName:
			f.StringVar(&base.StringVar{
				Name:   derefAliasesFlagName,
				Target: &c.flagDerefAliases,
				Usage:  "Control how aliases are dereferenced when performing the search. Possible values are: never, finding, searching, and always (optional).",
			})
		case accountAttributeMapsFlagName:
			f.StringSliceVar(&base.StringSliceVar{
				Name:   accountAttributeMapsFlagName,
				Target: &c.flagAccountAttributeMaps,
				Usage:  "Attribute maps from custom attributes to the standard fullName and email account attributes. These maps are represented as key=value where the key equals the from_attribute, and the value equals the to_attribute.",
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
				c.UI.Error(fmt.Sprintf("scheme in url %q is neither ldap nor ldaps", urlString))
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

	switch c.flagDerefAliases {
	case "":
	case "null":
		*opts = append(*opts, authmethods.DefaultLdapAuthMethodDereferenceAliases())
	default:
		// never, finding, searching, and always
		var derefAliases ldap.DerefAliasType
		switch strings.ToLower(c.flagDerefAliases) {
		case "never":
			derefAliases = ldap.NeverDerefAliases
		case "finding":
			derefAliases = ldap.DerefFindingBaseObj
		case "searching":
			derefAliases = ldap.DerefInSearching
		case "always":
			derefAliases = ldap.DerefAlways
		default:
			c.UI.Error(fmt.Sprintf("%q is an invalid deref aliases (valid values are: never, finding, searching or always)", c.flagDerefAliases))
			return false
		}
		*opts = append(*opts, authmethods.WithLdapAuthMethodDereferenceAliases(string(derefAliases)))
	}

	switch c.flagMaxPageSize {
	case 0:
		*opts = append(*opts, authmethods.DefaultLdapAuthMethodMaximumPageSize())
	default:
		*opts = append(*opts, authmethods.WithLdapAuthMethodMaximumPageSize(uint32(c.flagMaxPageSize)))
	}

	switch {
	case len(c.flagCertificates) == 0:
	case len(c.flagCertificates) == 1 && c.flagCertificates[0] == "null":
		*opts = append(*opts, authmethods.DefaultLdapAuthMethodCertificates())
	default:
		pems := make([]string, 0, len(c.flagCertificates))
		for _, certFlag := range c.flagCertificates {
			p, err := parseutil.MustParsePath(certFlag)
			switch {
			case err == nil:
				if validationErr := validateCerts(p); validationErr != nil {
					c.UI.Error(fmt.Sprintf("invalid certificate in %q: %s", certFlag, validationErr.Error()))
					return false
				}
				pems = append(pems, p)
			case errors.Is(err, parseutil.ErrNotParsed):
				c.UI.Error("Certificate flag must be used with env:// or file:// syntax")
				return false
			default:
				c.UI.Error(fmt.Sprintf("Error parsing certificate flag: %v", err))
				return false
			}
		}
		*opts = append(*opts, authmethods.WithLdapAuthMethodCertificates(pems))
	}

	switch c.flagClientCertificate {
	case "":
	case "null":
		*opts = append(*opts, authmethods.DefaultLdapAuthMethodClientCertificate())
	default:
		p, err := parseutil.MustParsePath(c.flagClientCertificate)
		switch {
		case err == nil:
			if validationErr := validateCerts(p); validationErr != nil {
				c.UI.Error(fmt.Sprintf("invalid client certificate in %q: %s", c.flagClientCertificate, validationErr.Error()))
				return false
			}
			*opts = append(*opts, authmethods.WithLdapAuthMethodClientCertificate(p))
		case errors.Is(err, parseutil.ErrNotParsed):
			c.UI.Error("Client certificate flag must be used with env:// or file:// syntax")
			return false
		default:
			c.UI.Error(fmt.Sprintf("Error parsing client certificate flag: %v", err))
			return false
		}
	}

	switch c.flagClientCertificateKey {
	case "":
	case "null":
		*opts = append(*opts, authmethods.DefaultLdapAuthMethodClientCertificateKey())
	default:
		key, err := parseutil.MustParsePath(c.flagClientCertificateKey)
		switch {
		case err == nil:
			*opts = append(*opts, authmethods.WithLdapAuthMethodClientCertificateKey(key))
		case errors.Is(err, parseutil.ErrNotParsed):
			c.UI.Error("Client certificate key flag must be used with env:// or file:// syntax")
			return false
		default:
			c.UI.Error(fmt.Sprintf("Error parsing client certificate key flag: %v", err))
			return false
		}
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
		password, err := parseutil.MustParsePath(c.flagBindPassword)
		switch {
		case err == nil:
			*opts = append(*opts, authmethods.WithLdapAuthMethodBindPassword(password))
		case errors.Is(err, parseutil.ErrNotParsed):
			c.UI.Error("Bind password flag must be used with env:// or file:// syntax")
			return false
		default:
			c.UI.Error(fmt.Sprintf("Error parsing bind password flag: %v", err))
			return false
		}
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

	switch c.flagState {
	case "":
		// there is a default value during "create", so it's okay to not
		// specify a state
	case "null":
		c.UI.Error("State is required, you cannot set it to null")
		return false
	default:
		*opts = append(*opts, authmethods.WithLdapAuthMethodState(c.flagState))
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
