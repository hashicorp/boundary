package credentialscmd

import (
	"github.com/hashicorp/boundary/api/credentials"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
)

func init() {
	extraSshPrivateKeyFlagsFunc = extraSshPrivateKeyFlagsFuncImpl
	extraSshPrivateKeyActionsFlagsMapFunc = extraSshPrivateKeyActionsFlagsMapFuncImpl
	extraSshPrivateKeyFlagsHandlingFunc = extraSshPrivateKeyFlagHandlingFuncImpl
}

type extraSshPrivateKeyCmdVars struct {
	flagUsername   string
	flagPrivateKey string
}

func extraSshPrivateKeyActionsFlagsMapFuncImpl() map[string][]string {
	flags := map[string][]string{
		"create": {
			usernameFlagName,
			privateKeyFlagName,
		},
	}
	flags["update"] = flags["create"]
	return flags
}

func extraSshPrivateKeyFlagsFuncImpl(c *SshPrivateKeyCommand, set *base.FlagSets, _ *base.FlagSet) {
	f := set.NewFlagSet("SSH Private Key Credential Options")

	for _, name := range flagsSshPrivateKeyMap[c.Func] {
		switch name {
		case usernameFlagName:
			f.StringVar(&base.StringVar{
				Name:   usernameFlagName,
				Target: &c.flagUsername,
				Usage:  "The username associated with the credential.",
			})
		case privateKeyFlagName:
			f.StringVar(&base.StringVar{
				Name:   privateKeyFlagName,
				Target: &c.flagPrivateKey,
				Usage:  "The SSH private key associated with the credential. This can be the value itself, refer to a file on disk (file://) from which the value will be read, or an env var (env://) from which the value will be read.",
			})
		}
	}
}

func extraSshPrivateKeyFlagHandlingFuncImpl(c *SshPrivateKeyCommand, _ *base.FlagSets, opts *[]credentials.Option) bool {
	switch c.flagUsername {
	case "":
	default:
		*opts = append(*opts, credentials.WithSshPrivateKeyCredentialUsername(c.flagUsername))
	}
	switch c.flagPrivateKey {
	case "":
	default:
		privateKey, err := parseutil.ParsePath(c.flagPrivateKey)
		if err != nil && err.Error() != parseutil.ErrNotAUrl.Error() {
			c.UI.Error("Error parsing private key flag: " + err.Error())
			return false
		}
		*opts = append(*opts, credentials.WithSshPrivateKeyCredentialPrivateKey(privateKey))
	}

	return true
}

func (c *SshPrivateKeyCommand) extraSshPrivateKeyHelpFunc(_ map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary credentials create ssh-private-key -credential-store-id [options] [args]",
			"",
			"  Create an SSH private key credential. Example:",
			"",
			`    $ boundary credentials create ssh-private-key -credential-store-id csvlt_1234567890 -username user -private-key file:///home/user/.ssh/id_ed25519`,
			"",
			"",
		})

	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary credentials update ssh-private-key [options] [args]",
			"",
			"  Update an SSH private key credential given its ID. Example:",
			"",
			`    $ boundary credentials update ssh-private-key -id clvlt_1234567890 -name devops -description "For DevOps usage"`,
			"",
			"",
		})
	}
	return helpStr + c.Flags().Help()
}
