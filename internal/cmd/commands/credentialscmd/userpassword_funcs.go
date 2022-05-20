package credentialscmd

import (
	"github.com/hashicorp/boundary/api/credentials"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func init() {
	extraUserpasswordFlagsFunc = extraUserPasswordFlagsFuncImpl
	extraUserpasswordActionsFlagsMapFunc = extraUserPasswordActionsFlagsMapFuncImpl
	extraUserpasswordFlagsHandlingFunc = extraUserPasswordFlagHandlingFuncImpl
}

const (
	usernameFlagName = "username"
	passwordFlagName = "password"
)

type extraUserpasswordCmdVars struct {
	flagUsername string
	flagPassword string
}

func extraUserPasswordActionsFlagsMapFuncImpl() map[string][]string {
	flags := map[string][]string{
		"create": {
			usernameFlagName,
			passwordFlagName,
		},
	}
	flags["update"] = flags["create"]
	return flags
}

func extraUserPasswordFlagsFuncImpl(c *UserpasswordCommand, set *base.FlagSets, _ *base.FlagSet) {
	f := set.NewFlagSet("User Password Credential Options")

	for _, name := range flagsUserpasswordMap[c.Func] {
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

func extraUserPasswordFlagHandlingFuncImpl(c *UserpasswordCommand, _ *base.FlagSets, opts *[]credentials.Option) bool {
	switch c.flagUsername {
	case "":
	default:
		*opts = append(*opts, credentials.WithUserPasswordCredentialUsername(c.flagUsername))
	}
	switch c.flagPassword {
	case "":
	default:
		*opts = append(*opts, credentials.WithUserPasswordCredentialPassword(c.flagPassword))
	}

	return true
}

func (c *UserpasswordCommand) extraUserpasswordHelpFunc(_ map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary credentials create user-password -credential-store-id [options] [args]",
			"",
			"  Create a user password credential. Example:",
			"",
			`    $ boundary credentials create user-password -credential-store-id csvlt_1234567890 -username user -password pass`,
			"",
			"",
		})

	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary credentials update user password [options] [args]",
			"",
			"  Update a user password credential given its ID. Example:",
			"",
			`    $ boundary credentials update user-password -id clvlt_1234567890 -name devops -description "For DevOps usage"`,
			"",
			"",
		})
	}
	return helpStr + c.Flags().Help()
}
