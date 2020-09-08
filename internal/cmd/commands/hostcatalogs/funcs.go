package hostcatalogs

import (
	"fmt"
	"time"

	"github.com/hashicorp/boundary/api/hostcatalogs"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func generateHostCatalogTableOutput(in *hostcatalogs.HostCatalog) string {
	var ret []string

	nonAttributeMap := map[string]interface{}{
		"ID":           in.Id,
		"Scope ID":     in.Scope.Id,
		"Version":      in.Version,
		"Type":         in.Type,
		"Created Time": in.CreatedTime.Local().Format(time.RFC3339),
		"Updated Time": in.UpdatedTime.Local().Format(time.RFC3339),
	}

	if in.Name != "" {
		nonAttributeMap["Name"] = in.Name
	}
	if in.Description != "" {
		nonAttributeMap["Description"] = in.Description
	}

	maxLength := 0
	for k := range nonAttributeMap {
		if len(k) > maxLength {
			maxLength = len(k)
		}
	}
	if len(in.Attributes) > 0 {
		for k, v := range in.Attributes {
			if attributeMap[k] != "" {
				in.Attributes[attributeMap[k]] = v
				delete(in.Attributes, k)
			}
		}
		for k := range in.Attributes {
			if len(k) > maxLength {
				maxLength = len(k)
			}
		}
	}

	ret = append(ret, "", "Host catalog information:")

	ret = append(ret,
		// We do +2 because there is another +2 offset for attributes below
		base.WrapMap(2, maxLength+2, nonAttributeMap),
	)

	if len(in.Attributes) > 0 {
		if true {
			ret = append(ret,
				fmt.Sprintf("  Attributes:   %s", ""),
			)
		}
		ret = append(ret,
			base.WrapMap(4, maxLength, in.Attributes),
		)
	}

	return base.WrapForHelpText(ret)
}

var attributeMap = map[string]string{}
