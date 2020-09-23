package authmethods

import (
	"time"

	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func addPasswordFlags(c *PasswordCommand, f *base.FlagSet) {
	f.StringVar(&base.StringVar{
		Name:   "min-login-name-length",
		Target: &c.flagMinLoginNameLength,
		Usage:  "The minimum length of login names",
	})
	f.StringVar(&base.StringVar{
		Name:   "min-password-length",
		Target: &c.flagMinPasswordLength,
		Usage:  "The minimum length of passwords",
	})
}

func generateAuthMethodTableOutput(in *authmethods.AuthMethod) string {
	nonAttributeMap := map[string]interface{}{
		"ID":           in.Id,
		"Version":      in.Version,
		"Type":         in.Type,
		"Created Time": in.CreatedTime.Local().Format(time.RFC1123),
		"Updated Time": in.UpdatedTime.Local().Format(time.RFC1123),
	}

	if in.Name != "" {
		nonAttributeMap["Name"] = in.Name
	}
	if in.Description != "" {
		nonAttributeMap["Description"] = in.Description
	}

	maxLength := base.MaxAttributesLength(nonAttributeMap, in.Attributes, keySubstMap)

	ret := []string{
		"",
		"Auth Method information:",
		base.WrapMap(2, maxLength+2, nonAttributeMap),
		"",
		"  Scope:",
		base.ScopeInfoForOutput(in.Scope, maxLength),
	}

	if len(in.Attributes) > 0 {
		ret = append(ret,
			"  Attributes:",
			base.WrapMap(4, maxLength, in.Attributes),
		)
	}

	return base.WrapForHelpText(ret)
}

var keySubstMap = map[string]string{
	"min_login_name_length": "Minimum Login Name Length",
	"min_password_length":   "Minimum Password Length",
}
