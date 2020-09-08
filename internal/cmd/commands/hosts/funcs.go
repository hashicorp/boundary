package hosts

import (
	"fmt"
	"time"

	"github.com/hashicorp/boundary/api/hosts"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func addStaticFlags(c *StaticCommand, f *base.FlagSet) {
	f.StringVar(&base.StringVar{
		Name:   "address",
		Target: &c.flagAddress,
		Usage:  "The address of the host",
	})
}

func generateHostTableOutput(in *hosts.Host) string {
	var ret []string

	nonAttributeMap := map[string]interface{}{
		"ID":              in.Id,
		"Version":         in.Version,
		"Type":            in.Type,
		"Created Time":    in.CreatedTime.Local().Format(time.RFC3339),
		"Updated Time":    in.UpdatedTime.Local().Format(time.RFC3339),
		"Host Catalog ID": in.HostCatalogId,
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

	ret = append(ret, "", "Host information:")

	ret = append(ret,
		// We do +2 because there is another +2 offset for attributes below
		base.WrapMap(2, maxLength+2, nonAttributeMap),
	)

	if len(in.HostSetIds) > 0 {
		if true {
			ret = append(ret,
				fmt.Sprintf("  Host Set IDs:"),
			)
		}
		ret = append(ret,
			base.WrapSlice(4, in.HostSetIds),
		)
	}

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
