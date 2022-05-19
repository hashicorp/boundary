package credentialscmd

import (
	"github.com/hashicorp/boundary/api/credentials"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func init() {
	extraUsernamePasswordFlagsFunc = extraUsernamePasswordFlagsFuncImpl
	extraUsernamePasswordActionsFlagsMapFunc = extraUsernamePasswordActionsFlagsMapFuncImpl
	extraUsernamePasswordFlagsHandlingFunc = extraUsernamePasswordFlagHandlingFuncImpl
}

const (
	usernameFlagName = "username"
	passwordFlagName = "password"
)

type extraUsernamePasswordCmdVars struct {
	flagUsername string
	flagPassword string
}

func extraUsernamePasswordActionsFlagsMapFuncImpl() map[string][]string {
	flags := map[string][]string{
		"create": {
			usernameFlagName,
			passwordFlagName,
		},
	}
	flags["update"] = flags["create"]
	return flags
}

func extraUsernamePasswordFlagsFuncImpl(c *UsernamePasswordCommand, set *base.FlagSets, _ *base.FlagSet) {
	f := set.NewFlagSet("User Password Credential Options")

	for _, name := range flagsUsernamePasswordMap[c.Func] {
		switch name {
		case usernameFlagName:
			f.StringVar(&base.StringVar{
				Name:   usernameFlagName,
				Target: &c.flagUsername,
				Usage:  "The username associated with the credential.",
			})
		case passwordFlagName:
			f.StringVar(&base.StringVar{
				Name:   passwordFlagName,
				Target: &c.flagPassword,
				Usage:  "The password associated with the credential.",
			})
		}
	}
}

func extraUsernamePasswordFlagHandlingFuncImpl(c *UsernamePasswordCommand, _ *base.FlagSets, opts *[]credentials.Option) bool {
	switch c.flagUsername {
	case "":
	default:
		*opts = append(*opts, credentials.WithUsernamePasswordCredentialUsername(c.flagUsername))
	}
	switch c.flagPassword {
	case "":
	default:
		*opts = append(*opts, credentials.WithUsernamePasswordCredentialPassword(c.flagPassword))
	}

	return true
}

func (c *UsernamePasswordCommand) extraUsernamePasswordHelpFunc(_ map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary credentials create username-password -credential-store-id [options] [args]",
			"",
			"  Create a user password credential. Example:",
			"",
			`    $ boundary credentials create username-password -credential-store-id csvlt_1234567890 -username user -password pass`,
			"",
			"",
		})

	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary credentials update user password [options] [args]",
			"",
			"  Update a user password credential given its ID. Example:",
			"",
			`    $ boundary credentials update username-password -id clvlt_1234567890 -name devops -description "For DevOps usage"`,
			"",
			"",
		})
	}
	return helpStr + c.Flags().Help()
}
