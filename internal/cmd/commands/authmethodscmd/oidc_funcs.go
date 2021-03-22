package authmethodscmd

import (
	"fmt"
	"strconv"

	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func init() {
	extraOidcActionsFlagsMapFunc = extraOidcActionsFlagsMapFuncImpl
	extraOidcFlagsFunc = extraOidcFlagsFuncImpl
	extraOidcFlagsHandlingFunc = extraOidcFlagHandlingFuncImpl
}

type extraOidcCmdVars struct {
	flagDiscoveryUrl      string
	flagClientSecret      string
	flagClientId          string
	flagCallbackUrlPrefix string
	flagAllowedAudiences  []string
	flagCertificates      []string
}

func extraOidcActionsFlagsMapFuncImpl() map[string][]string {
	return map[string][]string{
		"create": {"discovery-url", "client-secret", "client-id", "callback-url-prefix", "allowed-audiences", "certificates"},
		"update": {"discovery-url", "client-secret", "client-id", "callback-url-prefix", "allowed-audiences", "certificates"},
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
			`    $ boundary auth-methods update oidc -id ampw_1234567890 -name "devops" -description "Oidc auth-method for DevOps"`,
			"",
			"",
		})
	}
	return helpStr + c.Flags().Help()
}

func extraOidcFlagsFuncImpl(c *OidcCommand, set *base.FlagSets, f *base.FlagSet) {
	f = set.NewFlagSet("Oidc Auth Method Options")

	for _, name := range flagsOidcMap[c.Func] {
		switch name {
		case "min-login-name-length":
			f.StringVar(&base.StringVar{
				Name:   "min-login-name-length",
				Target: &c.flagMinLoginNameLength,
				Usage:  "The minimum length of login names",
			})
		case "min-oidc-length":
			f.StringVar(&base.StringVar{
				Name:   "min-oidc-length",
				Target: &c.flagMinOidcLength,
				Usage:  "The minimum length of oidcs",
			})
		}
	}
}

func extraOidcFlagHandlingFuncImpl(c *OidcCommand, opts *[]authmethods.Option) bool {
	var attributes map[string]interface{}
	addAttribute := func(name string, value interface{}) {
		if attributes == nil {
			attributes = make(map[string]interface{})
		}
		attributes[name] = value
	}
	switch c.flagMinLoginNameLength {
	case "":
	case "null":
		addAttribute("min_login_name_length", nil)
	default:
		length, err := strconv.ParseUint(c.flagMinLoginNameLength, 10, 32)
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error parsing %q: %s", c.flagMinLoginNameLength, err))
			return false
		}
		addAttribute("min_login_name_length", uint32(length))
	}

	switch c.flagMinPasswordLength {
	case "":
	case "null":
		addAttribute("min_oidc_length", nil)
	default:
		length, err := strconv.ParseUint(c.flagMinPasswordLength, 10, 32)
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error parsing %q: %s", c.flagMinPasswordLength, err))
			return false
		}
		addAttribute("min_oidc_length", uint32(length))
	}

	if attributes != nil {
		*opts = append(*opts, authmethods.WithAttributes(attributes))
	}

	return true
}
