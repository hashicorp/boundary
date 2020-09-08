package scopes

import (
	"time"

	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func generateScopeTableOutput(in *scopes.Scope) string {
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

	ret = append(ret, "", "Scope information:")

	ret = append(ret,
		base.WrapMap(2, 0, nonAttributeMap),
	)

	return base.WrapForHelpText(ret)
}
