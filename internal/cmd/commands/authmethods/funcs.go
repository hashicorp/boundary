package authmethods

import (
	"fmt"
	"time"

	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func addPasswordFlags(c *PasswordCommand, f *base.FlagSet) {
	f.StringVar(&base.StringVar{
		Name:   "password-min-login-name-length",
		EnvVar: "BOUNDARY_AUTH_METHOD_PASSWORD_MIN_LOGIN_NAME_LENGTH",
		Target: &c.flagPasswordMinLoginNameLength,
		Usage:  "The minimum length of login names",
	})
	f.StringVar(&base.StringVar{
		Name:   "password-min-password-length",
		EnvVar: "BOUNDARY_AUTH_METHOD_PASSWORD_MIN_PASSWORD_LENGTH",
		Target: &c.flagPasswordMinPasswordLength,
		Usage:  "The minimum length of passwords",
	})
}

func generateAuthMethodTableOutput(in *authmethods.AuthMethod) string {
	var ret []string
	// This if true is here to line up columns for easy editing
	if true {
		if true {
			ret = append(ret, []string{
				"",
				"User information:",
				fmt.Sprintf("  ID:           %s", in.Id),
				fmt.Sprintf("  Version:      %d", in.Version),
				fmt.Sprintf("  Type:         %s", in.Type),
				fmt.Sprintf("  Created Time: %s", in.CreatedTime.Local().Format(time.RFC3339)),
				fmt.Sprintf("  Updated Time: %s", in.UpdatedTime.Local().Format(time.RFC3339)),
			}...,
			)
		}
		if in.Name != "" {
			ret = append(ret,
				fmt.Sprintf("  Name:         %s", in.Name),
			)
		}
		if in.Description != "" {
			ret = append(ret,
				fmt.Sprintf("  Description:  %s", in.Description),
			)
		}
	}
	if len(in.Attributes) > 0 {
		if true {
			ret = append(ret,
				fmt.Sprintf("  Attributes:   %s", ""),
			)
		}
		for k, v := range in.Attributes {
			if attributeMap[k] != "" {
				k = attributeMap[k]
			}
			ret = append(ret,
				fmt.Sprintf("    %s: %s", k, v),
			)

		}
	}

	return base.WrapForHelpText(ret)
}

var attributeMap = map[string]string{
	"min_login_name_length": "Minimum Login Name Length",
	"min_password_length":   "Minimum Password Length",
}
