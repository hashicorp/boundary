package targets

import (
	"fmt"
	"time"

	"github.com/hashicorp/boundary/api/scopes"
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
				"",
			)
		}
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

var attributeMap = map[string]string{
	"default_port": "Default Port",
}

func exampleOutput() string {
	in := &targets.Target{
		Id:      "ttcp_1234567890",
		ScopeId: "global",
		Scope: &scopes.ScopeInfo{
			Id: "global",
		},
		Name:        "foo",
		Description: "The bar of foos",
		CreatedTime: time.Now().Add(-5 * time.Minute),
		UpdatedTime: time.Now(),
		Version:     3,
		Type:        "tcp",
		HostSetIds:  []string{"hsst_1234567890", "hsst_0987654321"},
		HostSets: []*targets.HostSet{
			{
				Id:            "hsst_1234567890",
				HostCatalogId: "hcst_1234567890",
			},
			{
				Id:            "hsst_0987654321",
				HostCatalogId: "hcst_1234567890",
			},
		},
		Attributes: map[string]interface{}{
			"default_port": 22,
		},
	}
	return generateTargetTableOutput(in)
}
