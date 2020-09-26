package accounts

import (
	"time"

	"github.com/hashicorp/boundary/api/accounts"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func generateAccountTableOutput(in *accounts.Account) string {
	nonAttributeMap := map[string]interface{}{
		"ID":             in.Id,
		"Version":        in.Version,
		"Type":           in.Type,
		"Created Time":   in.CreatedTime.Local().Format(time.RFC1123),
		"Updated Time":   in.UpdatedTime.Local().Format(time.RFC1123),
		"Auth Method ID": in.AuthMethodId,
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
		"Account information:",
		base.WrapMap(2, maxLength+2, nonAttributeMap),
		"  Scope:",
		base.ScopeInfoForOutput(in.Scope, maxLength),
	}

	if len(in.Attributes) > 0 {
		ret = append(ret,
			"",
			"  Attributes:",
			base.WrapMap(4, maxLength, in.Attributes),
		)
	}

	return base.WrapForHelpText(ret)
}

var keySubstMap = map[string]string{
	"login_name": "Login Name",
}
