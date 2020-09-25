package users

import (
	"time"

	"github.com/hashicorp/boundary/api/users"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func generateUserTableOutput(in *users.User) string {
	nonAttributeMap := map[string]interface{}{
		"ID":           in.Id,
		"Version":      in.Version,
		"Created Time": in.CreatedTime.Local().Format(time.RFC1123),
		"Updated Time": in.UpdatedTime.Local().Format(time.RFC1123),
	}

	if in.Name != "" {
		nonAttributeMap["Name"] = in.Name
	}
	if in.Description != "" {
		nonAttributeMap["Description"] = in.Description
	}

	maxLength := base.MaxAttributesLength(nonAttributeMap, nil, nil)

	ret := []string{
		"",
		"User information:",
		base.WrapMap(2, maxLength+2, nonAttributeMap),
		"",
		"  Scope:",
		base.ScopeInfoForOutput(in.Scope, maxLength),
	}

	return base.WrapForHelpText(ret)
}
