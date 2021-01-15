package scopes

import (
	"fmt"
	"sort"
	"time"

	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func generateScopeTableOutput(in *scopes.Scope) string {
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
		"Scope information:",
		base.WrapMap(2, maxLength+2, nonAttributeMap),
		"",
		"  Scope (parent):",
		base.ScopeInfoForOutput(in.Scope, maxLength),
	}

	if len(in.AuthorizedActions) > 0 {
		ret = append(ret,
			"",
			"  Authorized Actions:",
			base.WrapSlice(4, in.AuthorizedActions),
			"",
		)
	}

	if len(in.CollectionAuthorizedActions) > 0 {
		keys := make([]string, 0, len(in.CollectionAuthorizedActions))
		for k := range in.CollectionAuthorizedActions {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		ret = append(ret, "  Authorized Actions on Scope's Collections:")
		for _, key := range keys {
			ret = append(ret,
				fmt.Sprintf("    %ss:", key),
				base.WrapSlice(6, in.CollectionAuthorizedActions[key]),
			)
		}
	}

	return base.WrapForHelpText(ret)
}
