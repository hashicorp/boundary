package hostcatalogs

import (
	"time"

	"github.com/hashicorp/boundary/api/hostcatalogs"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func generateHostCatalogTableOutput(in *hostcatalogs.HostCatalog) string {
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
		"Host Catalog information:",
		base.WrapMap(2, maxLength+2, nonAttributeMap),
		"",
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
	"address": "Address",
}
