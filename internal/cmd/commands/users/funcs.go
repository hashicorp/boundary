package users

import (
	"time"

	"github.com/hashicorp/boundary/api/users"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func generateUserTableOutput(in *users.User) string {
	var ret []string

	nonAttributeMap := map[string]interface{}{
		"ID":           in.Id,
		"Scope ID":     in.Scope.Id,
		"Version":      in.Version,
		"Created Time": in.CreatedTime.Local().Format(time.RFC3339),
		"Updated Time": in.UpdatedTime.Local().Format(time.RFC3339),
	}

	if in.Name != "" {
		nonAttributeMap["Name"] = in.Name
	}
	if in.Description != "" {
		nonAttributeMap["Description"] = in.Description
	}

	ret = append(ret, "", "User information:")

	ret = append(ret,
		base.WrapMap(2, 0, nonAttributeMap),
	)

	return base.WrapForHelpText(ret)
}
