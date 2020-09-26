package targets

import (
	"time"

	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func generateTargetTableOutput(in *targets.Target) string {
	nonAttributeMap := map[string]interface{}{
		"ID":                       in.Id,
		"Version":                  in.Version,
		"Type":                     in.Type,
		"Created Time":             in.CreatedTime.Local().Format(time.RFC1123),
		"Updated Time":             in.UpdatedTime.Local().Format(time.RFC1123),
		"Session Connection Limit": in.SessionConnectionLimit,
		"Session Max Seconds":      in.SessionMaxSeconds,
	}

	if in.Name != "" {
		nonAttributeMap["Name"] = in.Name
	}
	if in.Description != "" {
		nonAttributeMap["Description"] = in.Description
	}

	maxLength := base.MaxAttributesLength(nonAttributeMap, in.Attributes, keySubstMap)

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

	ret := []string{
		"",
		"Target information:",
		base.WrapMap(2, maxLength+2, nonAttributeMap),
		"",
		"  Scope:",
		base.ScopeInfoForOutput(in.Scope, maxLength),
	}

	if len(in.HostSets) > 0 {
		ret = append(ret,
			"",
			"  Host Sets:",
		)
		for _, m := range hostSetMaps {
			ret = append(ret,
				base.WrapMap(4, maxLength, m),
				"",
			)
		}
	}

	if len(in.Attributes) > 0 {
		ret = append(ret,
			"  Attributes:",
			base.WrapMap(4, maxLength, in.Attributes),
		)
	}

	return base.WrapForHelpText(ret)
}

func generateAuthorizationTableOutput(in *targets.SessionAuthorization) string {
	var ret []string

	nonAttributeMap := map[string]interface{}{
		"Session ID":          in.SessionId,
		"Target ID":           in.TargetId,
		"Scope ID":            in.Scope.Id,
		"User ID":             in.UserId,
		"Host ID":             in.HostId,
		"Created Time":        in.CreatedTime.Local().Format(time.RFC3339),
		"Type":                in.Type,
		"Authorization Token": in.AuthorizationToken,
	}

	maxLength := 0
	for k := range nonAttributeMap {
		if len(k) > maxLength {
			maxLength = len(k)
		}
	}

	ret = append(ret, "", "Target information:")

	ret = append(ret,
		// We do +2 because there is another +2 offset for host sets below
		base.WrapMap(2, maxLength+2, nonAttributeMap),
	)

	return base.WrapForHelpText(ret)
}

var keySubstMap = map[string]string{
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
