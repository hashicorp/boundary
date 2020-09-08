package targets

import (
	"fmt"
	"time"

	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func generateTargetTableOutput(in *targets.Target) string {
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

	var hostSetMaps []map[string]interface{}
	if len(in.HostSets) > 0 {
		for _, set := range in.HostSets {
			m := map[string]interface{}{
				"ID":              set.Id,
				"Host Catalog ID": set.HostCatalogId,
			}
			hostSetMaps = append(hostSetMaps, m)
		}
		if l := len("Host Catalog ID"); l > maxLength {
			maxLength = l
		}
	}
	ret = append(ret, "", "Target information:")

	ret = append(ret,
		// We do +2 because there is another +2 offset for host sets below
		base.WrapMap(2, maxLength+2, nonAttributeMap),
	)

	if len(in.HostSets) > 0 {
		ret = append(ret,
			fmt.Sprintf("  Host Sets:   %s", ""),
		)
		for _, m := range hostSetMaps {
			ret = append(ret,
				base.WrapMap(4, maxLength, m),
			)
		}
	}

	return base.WrapForHelpText(ret)
}

var attributeMap = map[string]string{}
