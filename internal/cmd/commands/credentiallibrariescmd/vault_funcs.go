package credentiallibrariescmd

import (
	"github.com/hashicorp/boundary/api/credentiallibraries"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
)

func init() {
	extraVaultFlagsFunc = extraVaultFlagsFuncImpl
	extraVaultActionsFlagsMapFunc = extraVaultActionsFlagsMapFuncImpl
	extraVaultFlagsHandlingFunc = extraVaultFlagHandlingFuncImpl
}

const (
	pathFlagName            = "vault-path"
	httpMethodFlagName      = "vault-http-method"
	httpRequestBodyFlagName = "vault-http-request-body"
)

type extraVaultCmdVars struct {
	flagPath            string
	flagHttpMethod      string
	flagHttpRequestBody string
}

func extraVaultActionsFlagsMapFuncImpl() map[string][]string {
	flags := map[string][]string{
		"create": {
			pathFlagName,
			httpMethodFlagName,
			httpRequestBodyFlagName,
		},
	}
	flags["update"] = flags["create"]
	return flags
}

func extraVaultFlagsFuncImpl(c *VaultCommand, set *base.FlagSets, _ *base.FlagSet) {
	f := set.NewFlagSet("Vault Credential Library Options")

	for _, name := range flagsVaultMap[c.Func] {
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
		}
	}
}

func extraVaultFlagHandlingFuncImpl(c *VaultCommand, f *base.FlagSets, opts *[]credentiallibraries.Option) bool {
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

	return true
}

func (c *VaultCommand) extraVaultHelpFunc(helpMap map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary credential-libraries create vault -credential-store-id [options] [args]",
			"",
			"  Create a vault-type credential library. Example:",
			"",
			`    $ boundary credential-libraries create vault -credential-store-id csvlt_1234567890 -vault-path "/some/path"`,
			"",
			"",
		})

	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary credential-libraries update vault [options] [args]",
			"",
			"  Update a vault-type credential library given its ID. Example:",
			"",
			`    $ boundary credential-libraries update vault -id clvlt_1234567890 -name devops -description "For DevOps usage"`,
			"",
			"",
		})
	}
	return helpStr + c.Flags().Help()
}
